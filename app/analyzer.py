"""LoadBalancer Local 策略接流判定。

输入为已解析的 NodeInfo / ServiceInfo / EndpointSlice 原始对象，
逐「就绪节点 × Service TCP 端口」给出接流结论：

* accept            有 ready 后端，可接流
* terminating_only  无 ready，但有 serving 且 terminating 的后端，仅终止兜底
* unavailable       两类后端都没有，无可用后端
* unconfirmed       不同切片记录对同一后端（IP + 目标端口）说法不一，
                    且采用不同记录会改变本节点端口的结论

同一端口下，后端 IP 与目标端口相同的记录视为同一后端。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import (
    SERVICE_LABEL,
    EndpointRecord,
    NodeInfo,
    ServiceInfo,
    ServicePort,
    iter_slice_records,
)

STATUS_ACCEPT = "accept"
STATUS_TERMINATING_ONLY = "terminating_only"
STATUS_UNAVAILABLE = "unavailable"
STATUS_UNCONFIRMED = "unconfirmed"

# 结论的乐观程度：可接流 > 仅终止兜底 > 无可用后端
_RANK = {
    STATUS_ACCEPT: 3,
    STATUS_TERMINATING_ONLY: 2,
    STATUS_UNAVAILABLE: 1,
}


@dataclass
class BackendGroup:
    """同一后端（IP + 目标端口）在多条切片记录下的合并视图。"""
    ip: str
    target_port: int
    slice_names: list[str] = field(default_factory=list)
    state_variants: set[tuple[bool, bool, bool]] = field(default_factory=set)

    @property
    def ambiguous(self) -> bool:
        return len(self.state_variants) > 1

    def _rank(self, optimistic: bool) -> int:
        ranks = [_state_rank(v) for v in self.state_variants]
        return max(ranks) if optimistic else min(ranks)

    def best_rank(self) -> int:
        return self._rank(optimistic=True)

    def worst_rank(self) -> int:
        return self._rank(optimistic=False)


def _state_rank(variant: tuple[bool, bool, bool]) -> int:
    ready, serving, terminating = variant
    if ready:
        return _RANK[STATUS_ACCEPT]
    if serving and terminating:
        return _RANK[STATUS_TERMINATING_ONLY]
    return _RANK[STATUS_UNAVAILABLE]


def _rank_to_status(rank: int) -> str:
    for status, value in _RANK.items():
        if value == rank:
            return status
    return STATUS_UNAVAILABLE


@dataclass
class NodePortResult:
    node: str
    port_name: str
    service_port: int
    target_ports: list[int]
    status: str
    ready_backend_count: int
    terminating_backend_count: int
    unavailable_backend_count: int
    backends: list[dict]
    conflicts: list[dict]
    note: str | None = None


@dataclass
class AnalysisResult:
    namespace: str
    service: str
    external_traffic_policy: str
    matched_slices: list[str]
    ready_nodes: list[str]
    skipped_nodes: list[dict]
    node_ports: list[NodePortResult]
    diagnostics: list[str]


class TrafficAnalyzer:
    def __init__(
        self,
        nodes: list[NodeInfo],
        service: ServiceInfo,
        raw_slices: list[dict],
    ):
        self.nodes = nodes
        self.service = service
        self.raw_slices = raw_slices
        self.diagnostics: list[str] = []
        self.matched_slices = self._select_slices()
        self.records: list[EndpointRecord] = iter_slice_records(self.matched_slices)
        self.node_names = {n.name for n in nodes}

    # ------------------------------------------------------------------ #
    def _select_slices(self) -> list[dict]:
        """按命名空间 + service-name 标签关联属于该 Service 的切片。"""
        matched: list[dict] = []
        for raw in self.raw_slices:
            metadata = raw.get("metadata") or {}
            if (metadata.get("namespace") or "default") != self.service.namespace:
                continue
            labels = metadata.get("labels") or {}
            if labels.get(SERVICE_LABEL) != self.service.name:
                continue
            matched.append(raw)
        if not matched:
            self.diagnostics.append(
                f"命名空间 {self.service.namespace} 下没有标签 "
                f"{SERVICE_LABEL}={self.service.name} 的 EndpointSlice"
            )
        return matched

    # ------------------------------------------------------------------ #
    def _match_slice_ports(self, svc_port: ServicePort) -> list[tuple[int, str | None, str]]:
        """返回与 Service 端口关联的 (目标端口号, 切片端口名, 切片名) 列表。"""
        out: list[tuple[int, str | None, str]] = []
        for raw in self.matched_slices:
            slice_name = (raw.get("metadata") or {}).get("name") or "<unknown>"
            for sp in raw.get("ports") or []:
                if not isinstance(sp, dict):
                    continue
                if str(sp.get("protocol", "TCP")).upper() != "TCP":
                    continue
                port_no = sp.get("port")
                if not isinstance(port_no, int) or isinstance(port_no, bool):
                    continue
                sp_name = sp.get("name") if isinstance(sp.get("name"), str) else None
                if svc_port.target_port is not None:
                    # 数字 targetPort：按端口号匹配，与切片端口名无关。
                    if port_no == svc_port.target_port:
                        out.append((port_no, sp_name, slice_name))
                else:
                    # 字符串 targetPort：按切片端口名匹配。
                    if sp_name == svc_port.target_port_name:
                        out.append((port_no, sp_name, slice_name))
        return out

    # ------------------------------------------------------------------ #
    def analyze(self) -> AnalysisResult:
        ready = sorted((n for n in self.nodes if n.ready), key=lambda n: n.name)
        skipped = [
            {"name": n.name, "reason": "节点 Ready 条件不为 True，Local 策略不向其转发"}
            for n in sorted(self.nodes, key=lambda n: n.name)
            if not n.ready
        ]

        unknown_nodes = sorted({r.node for r in self.records if r.node and r.node not in self.node_names})
        if unknown_nodes:
            self.diagnostics.append(
                "切片中存在 NodeList 未涵盖的节点后端，已忽略: " + ", ".join(unknown_nodes)
            )

        node_ports: list[NodePortResult] = []
        for node in ready:
            for svc_port in self.service.ports:
                node_ports.append(self._analyze_node_port(node.name, svc_port))

        return AnalysisResult(
            namespace=self.service.namespace,
            service=self.service.name,
            external_traffic_policy=self.service.traffic_policy,
            matched_slices=sorted(
                {(raw.get("metadata") or {}).get("name") or "<unknown>" for raw in self.matched_slices}
            ),
            ready_nodes=[n.name for n in ready],
            skipped_nodes=skipped,
            node_ports=node_ports,
            diagnostics=self.diagnostics,
        )

    # ------------------------------------------------------------------ #
    def _analyze_node_port(self, node_name: str, svc_port: ServicePort) -> NodePortResult:
        matched_ports = self._match_slice_ports(svc_port)
        target_ports = sorted({p for p, _, _ in matched_ports})
        conflicts: list[dict] = []
        note: str | None = None

        if not matched_ports:
            if not self.matched_slices:
                note = "没有关联到该 Service 的 EndpointSlice"
            elif svc_port.target_port_name is not None:
                note = f"关联切片中没有名为 {svc_port.target_port_name!r} 的 TCP 端口"
            else:
                note = f"关联切片中没有目标端口 {svc_port.target_port} 的 TCP 端口"
            return NodePortResult(
                node=node_name,
                port_name=svc_port.name,
                service_port=svc_port.port,
                target_ports=[],
                status=STATUS_UNAVAILABLE,
                ready_backend_count=0,
                terminating_backend_count=0,
                unavailable_backend_count=0,
                backends=[],
                conflicts=[],
                note=note,
            )

        # 字符串 targetPort 可能在不同切片里解析出不同的实际端口号。
        port_definition_conflict = len(target_ports) > 1
        if port_definition_conflict:
            conflicts.append({
                "type": "target_port_conflict",
                "message": (
                    f"端口名 {svc_port.target_port_name!r} 在不同切片中对应不同目标端口: "
                    + ", ".join(str(p) for p in target_ports)
                ),
                "target_ports": target_ports,
            })

        matched_keys = {(p, s) for p, _, s in matched_ports}
        node_records = [
            r for r in self.records
            if r.node == node_name and (r.target_port, r.slice_name) in matched_keys
        ]

        groups = self._group_backends(node_records)

        # 同一后端（IP + 目标端口）在多条记录里条件不一致。
        for group in groups:
            if group.ambiguous:
                conflicts.append({
                    "type": "duplicate_backend_conflict",
                    "message": (
                        f"后端 {group.ip}:{group.target_port} 在切片 "
                        f"{', '.join(group.slice_names)} 中的 ready/serving/terminating 条件不一致"
                    ),
                    "ip": group.ip,
                    "target_port": group.target_port,
                    "slice_names": list(group.slice_names),
                    "states": [
                        {"ready": rdy, "serving": srv, "terminating": term}
                        for (rdy, srv, term) in sorted(group.state_variants)
                    ],
                })

        status = self._conclude(groups, target_ports, node_records,
                                port_definition_conflict, conflicts)

        ready_count = sum(1 for g in groups if any(v[0] for v in g.state_variants))
        terminating_count = sum(
            1 for g in groups
            if not any(v[0] for v in g.state_variants)
            and any(v[1] and v[2] for v in g.state_variants)
        )
        unavailable_count = sum(
            1 for g in groups
            if not any(v[0] for v in g.state_variants)
            and not any(v[1] and v[2] for v in g.state_variants)
        )

        return NodePortResult(
            node=node_name,
            port_name=svc_port.name,
            service_port=svc_port.port,
            target_ports=target_ports,
            status=status,
            ready_backend_count=ready_count,
            terminating_backend_count=terminating_count,
            unavailable_backend_count=unavailable_count,
            backends=[self._serialize_group(g) for g in groups],
            conflicts=conflicts,
            note=note,
        )

    # ------------------------------------------------------------------ #
    @staticmethod
    def _group_backends(records: list[EndpointRecord]) -> list[BackendGroup]:
        groups: dict[tuple[str, int], BackendGroup] = {}
        for r in records:
            key = (r.address, r.target_port)
            group = groups.get(key)
            if group is None:
                group = BackendGroup(ip=r.address, target_port=r.target_port)
                groups[key] = group
            if r.slice_name not in group.slice_names:
                group.slice_names.append(r.slice_name)
            group.state_variants.add((r.ready, r.serving, r.terminating))
        return sorted(groups.values(), key=lambda g: (g.ip, g.target_port))

    def _conclude(
        self,
        groups: list[BackendGroup],
        target_ports: list[int],
        node_records: list[EndpointRecord],
        port_definition_conflict: bool,
        conflicts: list[dict],
    ) -> str:
        """按「采用不同记录是否改变结论」决定最终状态。"""
        if not groups:
            # 端口定义冲突且本节点在某一个目标端口上没有任何后端：
            # 采用不同切片会在「无可用后端」与另一端口的结论间摇摆。
            if port_definition_conflict:
                return STATUS_UNCONFIRMED
            return STATUS_UNAVAILABLE

        # 视角一：合并后的总体结论（与值班员直观口径一致）。
        merged_rank = max(
            (
                _RANK[STATUS_ACCEPT]
                if any(v[0] for v in g.state_variants)
                else _RANK[STATUS_TERMINATING_ONLY]
                if any(v[1] and v[2] for v in g.state_variants)
                else _RANK[STATUS_UNAVAILABLE]
                for g in groups
            ),
            default=_RANK[STATUS_UNAVAILABLE],
        )

        # 视角二：每个后端取最不利记录时的结论。
        worst_rank = max((g.worst_rank() for g in groups), default=_RANK[STATUS_UNAVAILABLE])
        best_rank = max((g.best_rank() for g in groups), default=_RANK[STATUS_UNAVAILABLE])

        if port_definition_conflict:
            # 逐目标端口分别下结论；任一端口结论不同即无法确认。
            per_port = []
            for port_no in target_ports:
                sub_records = [r for r in node_records if r.target_port == port_no]
                sub_groups = self._group_backends(sub_records)
                if not sub_groups:
                    per_port.append(_RANK[STATUS_UNAVAILABLE])
                else:
                    per_port.append(max(
                        (
                            _RANK[STATUS_ACCEPT]
                            if any(v[0] for v in g.state_variants)
                            else _RANK[STATUS_TERMINATING_ONLY]
                            if any(v[1] and v[2] for v in g.state_variants)
                            else _RANK[STATUS_UNAVAILABLE]
                            for g in sub_groups
                        )
                    ))
            if len(set(per_port)) > 1:
                return STATUS_UNCONFIRMED

        if best_rank != worst_rank:
            return STATUS_UNCONFIRMED
        return _rank_to_status(merged_rank)

    # ------------------------------------------------------------------ #
    @staticmethod
    def _serialize_group(group: BackendGroup) -> dict:
        ready = any(v[0] for v in group.state_variants)
        terminating = (
            not ready and any(v[1] and v[2] for v in group.state_variants)
        )
        return {
            "ip": group.ip,
            "target_port": group.target_port,
            "ready": ready,
            "terminating_only": terminating,
            "ambiguous": group.ambiguous,
            "slice_names": list(group.slice_names),
            "states": [
                {"ready": rdy, "serving": srv, "terminating": term}
                for (rdy, srv, term) in sorted(group.state_variants)
            ],
        }


def analyze(nodes: list[NodeInfo], service: ServiceInfo, raw_slices: list[dict]) -> AnalysisResult:
    return TrafficAnalyzer(nodes, service, raw_slices).analyze()
