#include "avbehavior/process_tree.hpp"

namespace avbehavior {

void ProcessTree::OnProcessCreate(const ProcessEvent& event) {
    nodes_[event.process_id] = ProcessNode{event};
}

void ProcessTree::OnProcessExit(std::uint32_t process_id) {
    nodes_.erase(process_id);
}

std::optional<ProcessNode> ProcessTree::Get(std::uint32_t process_id) const {
    auto it = nodes_.find(process_id);
    if (it == nodes_.end()) return std::nullopt;
    return it->second;
}

std::optional<ProcessNode> ProcessTree::GetParent(std::uint32_t process_id) const {
    auto self = Get(process_id);
    if (!self) return std::nullopt;
    return Get(self->event.parent_process_id);
}

} // namespace avbehavior
