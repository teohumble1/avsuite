#pragma once

#include <cstdint>
#include <optional>
#include <unordered_map>

#include "avbehavior/process_event.hpp"

namespace avbehavior {

struct ProcessNode {
    ProcessEvent event;
};

// Tracks live process lineage so rules can answer "who is my parent" without
// re-deriving it from raw events. Keyed by PID, but PIDs are recycled by
// Windows -- callers must tolerate a node being replaced when a new process
// reuses an old PID (start_time on the stored event disambiguates if needed).
class ProcessTree {
public:
    void OnProcessCreate(const ProcessEvent& event);
    void OnProcessExit(std::uint32_t process_id);

    std::optional<ProcessNode> Get(std::uint32_t process_id) const;
    std::optional<ProcessNode> GetParent(std::uint32_t process_id) const;

    std::size_t Size() const { return nodes_.size(); }

private:
    std::unordered_map<std::uint32_t, ProcessNode> nodes_;
};

} // namespace avbehavior
