"""解析 NodeList / Service / EndpointSliceList 快照，提取接流判定所需的领域模型。

只依赖标准库；所有输入均视为不可信数据，解析阶段不执行任何外部代码。
本工具的判定范围：IPv4、externalTrafficPolicy=Local 的 LoadBalancer Service。
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

SERVICE_KIND = "Service"
ENDPOINT_SLICE_KIND = "EndpointSlice"
SERVICE_LABEL = "kubernetes.io/service-name"
PROTOCOL_TCP = "TCP"
PROTOCOL_UDP = "UDP"


class SnapshotError(ValueError):
    """快照结构或内容不满足判定前提时抛出。"""


def _items(payload: Any, label: str) -> list[dict]:
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        return [x for x in payload["items"] if isinstance(x, dict)]
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    raise SnapshotError(f"{label} 既不是 Kubernetes List 对象（含 items），也不是数组")


def is_ipv4(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Node
# --------------------------------------------------------------------------- #
@dataclass
class NodeInfo:
    name: str
    ready: bool


def parse_nodes(payload: Any) -> list[NodeInfo]:
    nodes: list[NodeInfo] = []
    seen: set[str] = set()
    for raw in _items(payload, "NodeList"):
        metadata = raw.get("metadata") or {}
        name = metadata.get("name")
        if not isinstance(name, str) or not name:
            raise SnapshotError("NodeList 中存在缺少 metadata.name 的节点")
        if name in seen:
            raise SnapshotError(f"NodeList 中节点 {name} 重复出现")
        seen.add(name)
        ready = False
        for cond in (raw.get("status") or {}).get("conditions") or []:
            if isinstance(cond, dict) and cond.get("type") == "Ready":
                ready = cond.get("status") == "True"
        nodes.append(NodeInfo(name=name, ready=ready))
    if not nodes:
        raise SnapshotError("NodeList 中没有任何节点")
    return nodes


# --------------------------------------------------------------------------- #
# Service
# --------------------------------------------------------------------------- #
@dataclass
class ServicePort:
    name: str
    port: int
    target_port: int | None  # 数字 targetPort 直接给出；字符串则需到切片里按端口名匹配
    target_port_name: str | None


@dataclass
class ServiceInfo:
    namespace: str
    name: str
    traffic_policy: str
    ports: list[ServicePort]


def _as_port_number(value: Any) -> int:
    if isinstance(value, bool):
        raise SnapshotError(f"非法端口号: {value!r}")
    if isinstance(value, int) and 0 < value <= 65535:
        return value
    raise SnapshotError(f"非法端口号: {value!r}")


def parse_service(payload: Any) -> ServiceInfo:
    if not isinstance(payload, dict):
        raise SnapshotError("Service 快照必须是单个 Service 对象")
    if isinstance(payload.get("items"), list):
        raise SnapshotError("请上传单个 Service 对象，而不是 ServiceList")
    kind = payload.get("kind")
    if kind is not None and kind != SERVICE_KIND:
        raise SnapshotError(f"Service 快照 kind={kind!r}，期望 Service")

    metadata = payload.get("metadata") or {}
    spec = payload.get("spec") or {}
    namespace = metadata.get("namespace") or "default"
    name = metadata.get("name")
    if not isinstance(name, str) or not name:
        raise SnapshotError("Service 缺少 metadata.name")

    if spec.get("type") != "LoadBalancer":
        raise SnapshotError(f"仅支持 type=LoadBalancer 的 Service，当前为 {spec.get('type')!r}")
    policy = spec.get("externalTrafficPolicy")
    if policy != "Local":
        raise SnapshotError(
            f"仅支持 externalTrafficPolicy=Local，当前为 {policy!r}"
        )

    raw_ports = spec.get("ports")
    if not isinstance(raw_ports, list) or not raw_ports:
        raise SnapshotError("Service 没有声明任何 spec.ports")

    ports: list[ServicePort] = []
    seen_names: set[str] = set()
    for raw_port in raw_ports:
        if not isinstance(raw_port, dict):
            raise SnapshotError("Service spec.ports 中存在非对象条目")
        protocol = str(raw_port.get("protocol", PROTOCOL_TCP)).upper()
        if protocol != PROTOCOL_TCP:
            # 本工具只看 TCP 端口；UDP/SCTP 直接跳过。
            continue
        port_name = raw_port.get("name")
        if not isinstance(port_name, str) or not port_name:
            raise SnapshotError(
                f"Service 端口 {raw_port.get('port')!r} 缺少 name；Local 策略按端口名关联切片，端口必须命名"
            )
        if port_name in seen_names:
            raise SnapshotError(f"Service 存在同名 TCP 端口 {port_name!r}")
        seen_names.add(port_name)
        port_no = _as_port_number(raw_port.get("port"))

        target = raw_port.get("targetPort", port_no)
        target_port = target_port_name = None
        if isinstance(target, bool):
            raise SnapshotError(f"端口 {port_name} 的 targetPort 非法: {target!r}")
        if isinstance(target, int):
            target_port = _as_port_number(target)
        elif isinstance(target, str) and target:
            if target.isdigit():
                target_port = _as_port_number(int(target))
            else:
                target_port_name = target
        else:
            raise SnapshotError(f"端口 {port_name} 的 targetPort 非法: {target!r}")
        ports.append(ServicePort(
            name=port_name,
            port=port_no,
            target_port=target_port,
            target_port_name=target_port_name,
        ))

    if not ports:
        raise SnapshotError("Service 没有任何 TCP 端口，无法判定接流状态")
    return ServiceInfo(
        namespace=namespace,
        name=name,
        traffic_policy=policy,
        ports=ports,
    )


# --------------------------------------------------------------------------- #
# EndpointSlice
# --------------------------------------------------------------------------- #
@dataclass
class SlicePort:
    name: str | None
    port: int
    protocol: str


@dataclass
class EndpointRecord:
    """一条后端记录：某个 IPv4 地址（后端 IP）+ 切片端口（目标端口）。"""
    slice_name: str
    address: str
    target_port: int
    port_name: str | None
    node: str | None
    ready: bool
    serving: bool
    terminating: bool


@dataclass
class EndpointSliceData:
    slices: list[dict] = field(default_factory=list)


def parse_endpoint_slices(payload: Any) -> list[dict]:
    slices = _items(payload, "EndpointSliceList")
    if not slices:
        raise SnapshotError("EndpointSliceList 中没有任何切片")
    names: set[str] = set()
    for raw in slices:
        kind = raw.get("kind")
        if kind is not None and kind != ENDPOINT_SLICE_KIND:
            raise SnapshotError(f"切片 {raw.get('metadata', {}).get('name')!r} kind={kind!r}，期望 EndpointSlice")
        name = (raw.get("metadata") or {}).get("name") or "<unknown>"
        if name in names:
            raise SnapshotError(f"EndpointSliceList 中切片 {name} 重复出现")
        names.add(name)
    return slices


def _endpoint_flag(endpoint: dict, key: str) -> bool:
    """EndpointSlice 条件三态：true/false；缺省（None）按 false 处理。"""
    value = (endpoint.get("conditions") or {}).get(key)
    return value is True


def iter_slice_records(raw_slices: list[dict]) -> list[EndpointRecord]:
    """把切片展开成 (IPv4 后端 IP, 切片端口) 粒度的记录，非 TCP / 非 IPv4 已剔除。"""
    records: list[EndpointRecord] = []
    for raw in raw_slices:
        metadata = raw.get("metadata") or {}
        slice_name = metadata.get("name") or "<unknown>"
        slice_ports: list[SlicePort] = []
        for sp in raw.get("ports") or []:
            if not isinstance(sp, dict):
                continue
            protocol = str(sp.get("protocol", PROTOCOL_TCP)).upper()
            if protocol != PROTOCOL_TCP:
                continue
            port_no = sp.get("port")
            if not isinstance(port_no, int) or isinstance(port_no, bool) or not (0 < port_no <= 65535):
                # 目标端口缺失/非法时无法定位后端，跳过该切片端口。
                continue
            slice_ports.append(SlicePort(
                name=sp.get("name") if isinstance(sp.get("name"), str) else None,
                port=port_no,
                protocol=protocol,
            ))

        for endpoint in raw.get("endpoints") or []:
            if not isinstance(endpoint, dict):
                continue
            node = endpoint.get("nodeName")
            node = node if isinstance(node, str) else None
            addresses = [a for a in (endpoint.get("addresses") or []) if is_ipv4(a)]
            if not addresses:
                # 限 IPv4：无 IPv4 地址的端点（IPv6/FQDN）不参与判定。
                continue
            ready = _endpoint_flag(endpoint, "ready")
            serving = _endpoint_flag(endpoint, "serving")
            terminating = _endpoint_flag(endpoint, "terminating")
            for address in addresses:
                for sp in slice_ports:
                    records.append(EndpointRecord(
                        slice_name=slice_name,
                        address=address,
                        target_port=sp.port,
                        port_name=sp.name,
                        node=node,
                        ready=ready,
                        serving=serving,
                        terminating=terminating,
                    ))
    return records
