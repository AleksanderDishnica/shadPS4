// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <algorithm>
#include <optional>
#include <span>
#include <string>
#include <boost/container/small_vector.hpp>
#include <boost/intrusive/set.hpp>

#include "common/assert.h"
#include "common/object_pool.h"
#include "common/types.h"
#include "shader_recompiler/frontend/instruction.h"
#include "shader_recompiler/ir/condition.h"

namespace Shader::IR {
class Block;
}

namespace Shader::Gcn {

using Hook =
    boost::intrusive::set_base_hook<boost::intrusive::link_mode<boost::intrusive::normal_link>>;

enum class EndClass {
    Branch, ///< Block ends with a (un)conditional branch.
    Exit,   ///< Block ends with an exit instruction.
};

/// A block represents a linear range of instructions.
struct Block : Hook {
    [[nodiscard]] bool Contains(u32 pc) const noexcept;

    bool operator<(const Block& rhs) const noexcept {
        return begin < rhs.begin;
    }

    u32 begin;
    u32 end;
    u32 begin_index;
    u32 end_index;
    u32 num_predecessors{};
    IR::Condition cond{};
    GcnInst end_inst{};
    EndClass end_class{};
    Block* branch_true{};
    Block* branch_false{};
    IR::Block* ir_block{};
    bool is_dummy{};
    // Jump-table switch compat: an S_SETPC_B64 dispatched through a PC-relative
    // jump table. LowerSwitches builds a chain of dummy blocks so each case
    // becomes a real conditional edge driven by the selector comparison.
    bool is_switch{};
    bool is_switch_dummy{};
    u32 switch_sel_sgpr{0xFFFFFFFF};
    u32 switch_selector_scale{1};
};

class CFG {
    using Label = u32;
    using BlockList = boost::intrusive::set<Block>;
    using iterator = BlockList::iterator;

public:
    explicit CFG(Common::ObjectPool<Block>& block_pool, std::span<const GcnInst> inst_list,
                 std::span<const u32> code_ = {}, std::span<const u32> data_tail_ = {});

    [[nodiscard]] iterator begin() {
        return blocks.begin();
    }
    [[nodiscard]] iterator end() {
        return blocks.end();
    }

    [[nodiscard]] std::string Dot() const;

private:
    void EmitLabels();
    void EmitBlocks();
    void LinkBlocks();
    void SplitDivergenceScopes();
    void RemoveUnreachableBlocks();

    // Compat: resolve an unresolvable S_SETPC_B64 through a PC-relative jump
    // table in the shader binary. Returns the first plausible target.
    [[nodiscard]] std::optional<u32> ResolveSetPcJumpTable(u32 setpc_index);

    struct SwitchInfo {
        boost::container::small_vector<u32, 8> targets;
        u32 sel_sgpr{0xFFFFFFFF};
        u32 scale{1};
    };
    // Resolve every jump-table target plus the selector register info.
    [[nodiscard]] std::optional<SwitchInfo> ResolveSetPcJumpTableFull(u32 setpc_index);

public:
    // Expand S_SETPC_B64 jump tables into chains of conditional edges through
    // synthetic dummy blocks. Must run after the CFG is fully built.
    void LowerSwitches();

    void AddLabel(Label address) {
        const auto it = std::ranges::find(labels, address);
        if (it == labels.end()) {
            labels.push_back(address);
        }
    }

    size_t GetIndex(Label label) {
        if (label == 0) {
            return 0ULL;
        }
        const auto it_index = std::ranges::lower_bound(index_to_pc, label);
        ASSERT(it_index != index_to_pc.end() || label > index_to_pc.back());
        return std::distance(index_to_pc.begin(), it_index);
    }

public:
    Common::ObjectPool<Block>& block_pool;
    std::span<const GcnInst> inst_list;
    std::span<const u32> code;
    std::span<const u32> data_tail;
    std::vector<u32> index_to_pc;
    boost::container::small_vector<Label, 16> labels;
    BlockList blocks;

    // Read a dword at a byte offset into the combined code + data tail.
    [[nodiscard]] const u32* DwordAt(u32 byte_offset) const noexcept {
        const u32 off = byte_offset / sizeof(u32);
        if (off < code.size()) {
            return &code[off];
        }
        const u32 tail_off = off - code.size();
        if (tail_off < data_tail.size()) {
            return &data_tail[tail_off];
        }
        return nullptr;
    }
};

} // namespace Shader::Gcn
