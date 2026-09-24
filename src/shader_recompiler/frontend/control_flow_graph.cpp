// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <algorithm>
#include <magic_enum/magic_enum.hpp>
#include "common/assert.h"
#include "common/logging/log.h"
#include "shader_recompiler/frontend/control_flow_graph.h"

namespace Shader::Gcn {

struct Compare {
    bool operator()(const Block& lhs, u32 rhs) const noexcept {
        return lhs.begin < rhs;
    }

    bool operator()(u32 lhs, const Block& rhs) const noexcept {
        return lhs < rhs.begin;
    }

    bool operator()(const Block& lhs, const Block& rhs) const noexcept {
        return lhs.begin < rhs.begin;
    }
};

static IR::Condition MakeCondition(const GcnInst& inst) {
    if (inst.IsCmpx()) {
        return IR::Condition::Execnz;
    }

    switch (inst.opcode) {
    case Opcode::S_CBRANCH_SCC0:
        return IR::Condition::Scc0;
    case Opcode::S_CBRANCH_SCC1:
        return IR::Condition::Scc1;
    case Opcode::S_CBRANCH_VCCZ:
        return IR::Condition::Vccz;
    case Opcode::S_CBRANCH_VCCNZ:
        return IR::Condition::Vccnz;
    case Opcode::S_CBRANCH_EXECZ:
        return IR::Condition::Execz;
    case Opcode::S_CBRANCH_EXECNZ:
        return IR::Condition::Execnz;
    default:
        return IR::Condition::True;
    }
}

static bool IgnoresExecMask(const GcnInst& inst) {
    // EXEC mask does not affect scalar instructions or branches.
    switch (inst.category) {
    case InstCategory::ScalarALU:
    case InstCategory::ScalarMemory:
    case InstCategory::FlowControl:
        return true;
    default:
        break;
    }
    // Read/Write Lane instructions are not affected either.
    switch (inst.opcode) {
    case Opcode::V_READLANE_B32:
    case Opcode::V_WRITELANE_B32:
    case Opcode::V_READFIRSTLANE_B32:
        return true;
    default:
        break;
    }
    return false;
}

static std::optional<u32> ResolveSetPcTarget(std::span<const GcnInst> list, u32 setpc_index,
                                             std::span<const u32> pc_map) {
    if (setpc_index < 3) {
        return std::nullopt;
    }

    const auto& getpc = list[setpc_index - 3];
    const auto& arith = list[setpc_index - 2];
    const auto& setpc = list[setpc_index];

    if (getpc.opcode != Opcode::S_GETPC_B64 ||
        !(arith.opcode == Opcode::S_ADD_U32 || arith.opcode == Opcode::S_SUB_U32) ||
        setpc.opcode != Opcode::S_SETPC_B64)
        return std::nullopt;

    if (getpc.dst[0].code != setpc.src[0].code || arith.dst[0].code != setpc.src[0].code)
        return std::nullopt;

    if (arith.src_count < 2 || arith.src[1].field != OperandField::LiteralConst)
        return std::nullopt;

    const u32 imm = arith.src[1].code;

    const s32 signed_offset =
        (arith.opcode == Opcode::S_ADD_U32) ? static_cast<s32>(imm) : -static_cast<s32>(imm);

    const u32 base_pc = pc_map[setpc_index - 3] + getpc.length;

    const u32 result_pc = static_cast<u32>(static_cast<s32>(base_pc) + signed_offset);
    LOG_DEBUG(Render_Recompiler, "SetPC target: {} + {} = {}", base_pc, signed_offset, result_pc);
    return result_pc & ~0x3u;
}

std::optional<u32> CFG::ResolveSetPcJumpTable(u32 setpc_index) {
    // Compat: resolve an unresolvable S_SETPC_B64 through a PC-relative jump
    // table: S_GETPC_B64; S_ADD_U32 imm (table pointer) ... S_LOAD_DWORDX2
    // ... S_GETPC_B64; S_ADD(reg)...; S_SETPC_B64. Targets in the table are
    // relative to the last GETPC. Returns the first plausible target.
    const u32 scan_start = setpc_index >= 12 ? setpc_index - 12 : 0;
    u32 table_addr = 0;
    bool have_table = false;
    u32 jump_base = 0;
    bool have_jump_base = false;
    for (u32 d = scan_start; d < setpc_index; ++d) {
        const auto& g = inst_list[d];
        if (g.opcode != Opcode::S_GETPC_B64) {
            continue;
        }
        const u32 gpc = index_to_pc[d] + g.length;
        // GETPC followed by ADD with a literal is the table pointer; any other
        // GETPC in the window is the jump base.
        if (d + 1 < setpc_index && inst_list[d + 1].opcode == Opcode::S_ADD_U32) {
            u32 imm = 0;
            bool has_imm = false;
            for (u32 s = 0; s < inst_list[d + 1].src_count && s < 2; ++s) {
                if (inst_list[d + 1].src[s].field == OperandField::LiteralConst) {
                    imm = inst_list[d + 1].src[s].code;
                    has_imm = true;
                    break;
                }
            }
            if (has_imm) {
                table_addr = gpc + imm;
                have_table = true;
                continue;
            }
        }
        jump_base = gpc;
        have_jump_base = true;
    }
    if (!have_table || !have_jump_base || table_addr % sizeof(u32) != 0) {
        return std::nullopt;
    }
    for (u32 e = 0; e < 16; ++e) {
        const u32* lo = DwordAt(table_addr + e * 8);
        const u32* hi = DwordAt(table_addr + e * 8 + 4);
        if (lo == nullptr || hi == nullptr) {
            break;
        }
        const u64 entry = (u64)*lo | ((u64)*hi << 32);
        const u32 cand = (u32)((s64)jump_base + (s64)entry);
        if (cand == 0 || cand % 4 != 0) {
            continue;
        }
        if (cand + 0x10 > code.size() * sizeof(u32)) {
            continue; // outside the shader
        }
        return cand;
    }
    return std::nullopt;
}

std::optional<CFG::SwitchInfo> CFG::ResolveSetPcJumpTableFull(u32 setpc_index) {
    const u32 scan_start = setpc_index >= 16 ? setpc_index - 16 : 0;
    u32 table_addr = 0;
    bool have_table = false;
    u32 jump_base = 0;
    bool have_jump_base = false;
    u32 sel_sgpr = 0xFFFFFFFF;
    u32 scale = 1;
    for (u32 d = scan_start; d < setpc_index; ++d) {
        const auto& g = inst_list[d];
        if (g.opcode == Opcode::S_LSHL_B32 && g.dst_count > 0 &&
            g.dst[0].field == OperandField::ScalarGPR) {
            // Candidate selector computation: index << scale
            sel_sgpr = g.dst[0].code;
            if (g.src_count > 1) {
                scale = 1u << (g.src[1].code & 0x1F);
            }
            continue;
        }
        if (g.opcode != Opcode::S_GETPC_B64) {
            continue;
        }
        const u32 gpc = index_to_pc[d] + g.length;
        // GETPC followed by ADD with a literal is the table pointer; any other
        // GETPC in the window is the jump base.
        if (d + 1 < setpc_index && inst_list[d + 1].opcode == Opcode::S_ADD_U32) {
            u32 imm = 0;
            bool has_imm = false;
            for (u32 s = 0; s < inst_list[d + 1].src_count && s < 2; ++s) {
                if (inst_list[d + 1].src[s].field == OperandField::LiteralConst) {
                    imm = inst_list[d + 1].src[s].code;
                    has_imm = true;
                    break;
                }
            }
            if (has_imm) {
                table_addr = gpc + imm;
                have_table = true;
                continue;
            }
        }
        jump_base = gpc;
        have_jump_base = true;
    }
    if (!have_table || !have_jump_base || table_addr % sizeof(u32) != 0) {
        return std::nullopt;
    }
    SwitchInfo info;
    info.sel_sgpr = sel_sgpr;
    info.scale = scale;
    for (u32 e = 0; e < 32; ++e) {
        const u32* lo = DwordAt(table_addr + e * 8);
        const u32* hi = DwordAt(table_addr + e * 8 + 4);
        if (lo == nullptr || hi == nullptr) {
            break;
        }
        const u64 entry = (u64)*lo | ((u64)*hi << 32);
        const u32 cand = (u32)((s64)jump_base + (s64)entry);
        if (cand == 0 || cand % 4 != 0 || cand + 0x10 > code.size() * sizeof(u32)) {
            break; // end of plausible table
        }
        if (std::ranges::find(info.targets, cand) == info.targets.end()) {
            info.targets.push_back(cand);
        }
    }
    if (info.targets.size() < 2) {
        return std::nullopt;
    }
    return info;
}

void CFG::LowerSwitches() {
    // Collect switch blocks first; inserting dummies while iterating the
    // intrusive set would invalidate iteration.
    boost::container::small_vector<Block*, 4> switch_blocks;
    for (auto& block : blocks) {
        if (block.end_inst.opcode == Opcode::S_SETPC_B64) {
            switch_blocks.push_back(&block);
        }
    }
    u32 synth_pc = 0x40000000u;
    for (Block* blk : switch_blocks) {
        auto sw = ResolveSetPcJumpTableFull(blk->end_index);
        if (!sw) {
            continue;
        }
        // All targets must exist as blocks (EmitLabels added labels for them).
        bool all_present = true;
        for (u32 t : sw->targets) {
            auto it = blocks.find(t, Compare{});
            if (it == blocks.end() || it->begin != t) {
                all_present = false;
                break;
            }
        }
        if (!all_present || !blk->branch_true) {
            continue;
        }
        if (blk->branch_true->begin != sw->targets[0]) {
            continue; // linking mismatch; keep the existing single target
        }
        blk->is_switch = true;
        blk->switch_sel_sgpr = sw->sel_sgpr;
        blk->switch_selector_scale = sw->scale;

        // Build the dummy chain dispatching targets[1..N-1]. The switch block
        // keeps branch_true = targets[0] and gains branch_false = dummy0. Each
        // dummy dispatches one case; the final dummy jumps unconditionally.
        Block* cur = blk;
        for (size_t i = 1; i < sw->targets.size(); ++i) {
            auto it = blocks.find(sw->targets[i], Compare{});
            Block* target = &*it;
            Block* dummy = block_pool.Create();
            dummy->begin = synth_pc;
            dummy->end = synth_pc;
            synth_pc += 4;
            dummy->begin_index = 1;
            dummy->end_index = 0; // empty instruction span
            dummy->end_class = EndClass::Branch;
            dummy->cond = IR::Condition::Scc0;
            dummy->end_inst = blk->end_inst;
            dummy->is_dummy = true;
            dummy->is_switch_dummy = true;
            dummy->switch_sel_sgpr = sw->sel_sgpr;
            dummy->switch_selector_scale = sw->scale;
            dummy->num_predecessors = 1; // reached from the previous chain node
            blocks.insert(*dummy);

            cur->branch_false = dummy;
            cur->cond = IR::Condition::Scc0;
            dummy->branch_true = target;
            target->num_predecessors++;
            cur = dummy;
        }
        // Make the final dispatch unconditional.
        cur->cond = IR::Condition::True;
        cur->branch_false = nullptr;
        LOG_WARNING(Render_Recompiler,
                    "Lowered S_SETPC_B64 jump table at PC {:#x}: {} cases, selector sgpr{} "
                    "(scale {:#x})",
                    blk->begin, sw->targets.size(), sw->sel_sgpr, sw->scale);
    }
}

static constexpr size_t LabelReserveSize = 32;

CFG::CFG(Common::ObjectPool<Block>& block_pool_, std::span<const GcnInst> inst_list_,
         std::span<const u32> code_, std::span<const u32> data_tail_)
    : block_pool{block_pool_}, inst_list{inst_list_}, code{code_}, data_tail{data_tail_} {
    index_to_pc.resize(inst_list.size() + 1);
    labels.reserve(LabelReserveSize);
    EmitLabels();
    EmitBlocks();
    LinkBlocks();
    SplitDivergenceScopes();
    // Lower jump-table switches before unreachable-block removal so all case
    // blocks are properly linked as predecessors and survive.
    LowerSwitches();
    RemoveUnreachableBlocks();
}

void CFG::EmitLabels() {
    // Always set a label at entry point.
    u32 pc = 0;
    AddLabel(pc);

    // Iterate instruction list and add labels to branch targets.
    for (u32 i = 0; i < inst_list.size(); i++) {
        index_to_pc[i] = pc;
        const GcnInst inst = inst_list[i];
        if (inst.IsUnconditionalBranch()) {
            u32 target = inst.BranchTarget(pc);
            if (inst.opcode == Opcode::S_SETPC_B64) {
                if (auto t = ResolveSetPcTarget(inst_list, i, index_to_pc)) {
                    target = *t;
                } else if (auto sw = ResolveSetPcJumpTableFull(i)) {
                    // Jump table: label every case target so blocks exist for
                    // all of them; LowerSwitches builds the dispatch chain.
                    LOG_WARNING(Render_Recompiler,
                                "S_SETPC_B64 jump table at PC {:#x}: {} cases", pc,
                                sw->targets.size());
                    for (u32 t : sw->targets) {
                        AddLabel(t);
                    }
                    target = sw->targets[0];
                } else {
                    // Compat: unresolvable S_SETPC_B64 — treat as block boundary.
                    LOG_WARNING(Render_Recompiler,
                                "S_SETPC_B64 unresolvable at PC {:#x} (Index {}): "
                                "treating as block boundary",
                                pc, i);
                    AddLabel(pc + inst.length);
                    pc += inst.length;
                    continue;
                }
            }
            AddLabel(target);
            // Emit this label so that the block ends with the branching instruction
            AddLabel(pc + inst.length);
        } else if (inst.IsConditionalBranch()) {
            const u32 true_label = inst.BranchTarget(pc);
            const u32 false_label = pc + inst.length;
            if (true_label != false_label) {
                AddLabel(true_label);
                AddLabel(false_label);
            }
        } else if (inst.opcode == Opcode::S_ENDPGM) {
            const u32 next_label = pc + inst.length;
            AddLabel(next_label);
        }

        pc += inst.length;
    }
    index_to_pc[inst_list.size()] = pc;

    // Sort labels to make sure block insertion is correct.
    std::ranges::sort(labels);
}

void CFG::SplitDivergenceScopes() {
    const auto is_open_scope = [](const GcnInst& inst) {
        // An open scope instruction is an instruction that modifies EXEC
        // but also saves the previous value to restore later. This indicates
        // we are entering a scope.
        return inst.opcode == Opcode::S_AND_SAVEEXEC_B64 ||
               // While this instruction does not save EXEC it is often used paired
               // with SAVEEXEC to mask the threads that didn't pass the condition
               // of initial branch.
               (inst.opcode == Opcode::S_ANDN2_B64 && inst.dst[0].field == OperandField::ExecLo) ||
               inst.IsCmpx();
    };
    const auto is_close_scope = [](const GcnInst& inst) {
        // Closing an EXEC scope can be either a branch instruction
        // (typical case when S_AND_SAVEEXEC_B64 is right before a branch)
        // or by a move instruction to EXEC that restores the backup.
        return (inst.opcode == Opcode::S_MOV_B64 && inst.dst[0].field == OperandField::ExecLo) ||
               // Sometimes compiler might insert instructions between the SAVEEXEC and the branch.
               // Those instructions need to be wrapped in the condition as well so allow branch
               // as end scope instruction.
               inst.opcode == Opcode::S_CBRANCH_EXECZ || inst.opcode == Opcode::S_ENDPGM ||
               (inst.opcode == Opcode::S_ANDN2_B64 && inst.dst[0].field == OperandField::ExecLo);
    };

    for (auto blk = blocks.begin(); blk != blocks.end(); blk++) {
        auto next_blk = std::next(blk);
        s32 curr_begin = -1;
        for (size_t index = blk->begin_index; index <= blk->end_index; index++) {
            const auto& inst = inst_list[index];
            const bool is_close = is_close_scope(inst);
            if ((is_close || index == blk->end_index) && curr_begin != -1) {
                // If there are no instructions inside scope don't do anything.
                if (index - curr_begin == 1 && is_close) {
                    curr_begin = -1;
                    continue;
                }
                // If all instructions in the scope ignore exec masking, we shouldn't insert a
                // scope.
                const auto start = inst_list.begin() + curr_begin + 1;
                if (!std::ranges::all_of(start, inst_list.begin() + index + !is_close,
                                         IgnoresExecMask)) {
                    // Determine the first instruction affected by the exec mask.
                    do {
                        ++curr_begin;
                    } while (IgnoresExecMask(inst_list[curr_begin]));

                    // Determine the last instruction affected by the exec mask.
                    s32 curr_end = index;
                    while (IgnoresExecMask(inst_list[curr_end])) {
                        --curr_end;
                    }

                    // Create a new block for the divergence scope.
                    Block* block = block_pool.Create();
                    block->begin = index_to_pc[curr_begin];
                    block->end = index_to_pc[curr_end];
                    block->begin_index = curr_begin;
                    block->end_index = curr_end;
                    block->end_inst = inst_list[curr_end];
                    block->num_predecessors = 1;
                    blocks.insert_before(next_blk, *block);

                    // If we are inside the parent block, make an epilogue block and jump to it.
                    if (curr_end != blk->end_index) {
                        Block* epi_block = block_pool.Create();
                        epi_block->begin = index_to_pc[curr_end + 1];
                        epi_block->end = blk->end;
                        epi_block->begin_index = curr_end + 1;
                        epi_block->end_index = blk->end_index;
                        epi_block->end_inst = blk->end_inst;
                        epi_block->cond = blk->cond;
                        epi_block->end_class = blk->end_class;
                        epi_block->branch_true = blk->branch_true;
                        epi_block->branch_false = blk->branch_false;
                        epi_block->num_predecessors = 2;
                        blocks.insert_before(next_blk, *epi_block);

                        // Have divergence block always jump to epilogue block.
                        block->cond = IR::Condition::True;
                        block->branch_true = epi_block;
                        block->branch_false = nullptr;

                        // If the parent block fails to enter divergence block make it jump to
                        // epilogue too
                        blk->branch_false = epi_block;
                    } else {
                        // No epilogue block is needed since the divergence block
                        // also ends the parent block. Inherit the end condition.
                        auto& parent_blk = *blk;
                        ASSERT(blk->cond == IR::Condition::True && blk->branch_true);
                        block->cond = IR::Condition::True;
                        block->branch_true = blk->branch_true;
                        block->branch_false = nullptr;

                        // If the parent block didn't enter the divergence scope
                        // have it jump directly to the next one
                        blk->branch_false = blk->branch_true;
                        blk->branch_true->num_predecessors++;
                    }

                    // Shrink parent block to end right before curr_begin
                    // and make it jump to divergence block
                    --curr_begin;
                    blk->end = index_to_pc[curr_begin];
                    blk->end_index = curr_begin;
                    blk->end_inst = inst_list[curr_begin];
                    blk->cond = IR::Condition::Execnz;
                    blk->end_class = EndClass::Branch;
                    blk->branch_true = block;
                }
                // Reset scope begin.
                curr_begin = -1;
            }
            // Mark a potential start of an exec scope.
            if (is_open_scope(inst)) {
                curr_begin = index;
            }
        }
    }
}

void CFG::EmitBlocks() {
    for (auto it = labels.cbegin(); it != labels.cend(); ++it) {
        const Label start = *it;
        const auto next_it = std::next(it);
        const bool is_last = (next_it == labels.cend());
        if (is_last) {
            // Last label is special.
            return;
        }
        // The end label is the start instruction of next block.
        // The end instruction of this block is the previous one.
        const Label end = *next_it;
        const size_t end_index = GetIndex(end) - 1;
        const auto& end_inst = inst_list[end_index];

        // Insert block between the labels using the last instruction
        // as an indicator for branching type.
        Block* block = block_pool.Create();
        block->begin = start;
        block->end = end;
        block->begin_index = GetIndex(start);
        block->end_index = end_index;
        block->end_inst = end_inst;
        block->cond = MakeCondition(end_inst);
        blocks.insert(*block);
    }
}

void CFG::LinkBlocks() {
    const auto get_block = [this](u32 address) {
        auto it = blocks.find(address, Compare{});
        ASSERT_MSG(it != blocks.cend() && it->begin == address);
        return &*it;
    };

    for (auto it = blocks.begin(); it != blocks.end(); it++) {
        auto& block = *it;
        const auto end_inst{block.end_inst};

        // If the block doesn't end with a branch we simply
        // need to link with the next block.
        if (!end_inst.IsTerminateInstruction()) {
            auto* next_block = get_block(block.end);
            block.branch_true = next_block;
            block.end_class = EndClass::Branch;
            next_block->num_predecessors++;
            continue;
        }

        // Find the branch targets from the instruction and link the blocks.
        // Note: Block end address is one instruction after end_inst.
        const u32 branch_pc = block.end - end_inst.length;
        u32 target_pc = 0;
        if (end_inst.opcode == Opcode::S_SETPC_B64) {
            auto tgt = ResolveSetPcTarget(inst_list, block.end_index, index_to_pc);
            if (tgt) {
                target_pc = *tgt;
            } else if (auto table_tgt = ResolveSetPcJumpTable(block.end_index)) {
                target_pc = *table_tgt;
            } else {
                // Compat: unresolvable S_SETPC_B64 (indirect branch through
                // runtime data). End the shader path here — an Exit block is
                // structurally valid for every downstream pass, unlike
                // fallthrough edges into unreached code.
                block.end_class = EndClass::Exit;
                block.branch_true = nullptr;
                block.branch_false = nullptr;
                LOG_WARNING(Render_Recompiler,
                            "S_SETPC_B64 without resolvable offset at PC {:#x} (Index {}): "
                            "ending shader path",
                            branch_pc, block.end_index);
                continue;
            }
        } else {
            target_pc = end_inst.BranchTarget(branch_pc);
        }

        if (end_inst.IsUnconditionalBranch()) {
            auto* target_block = get_block(target_pc);
            block.branch_true = target_block;
            block.end_class = EndClass::Branch;
            target_block->num_predecessors++;
        } else if (end_inst.IsConditionalBranch()) {
            auto* target_block = get_block(target_pc);
            auto* end_block = get_block(block.end);
            block.branch_true = target_block;
            block.branch_false = end_block;
            block.end_class = EndClass::Branch;
            target_block->num_predecessors++;
            end_block->num_predecessors++;
        } else if (end_inst.opcode == Opcode::S_ENDPGM) {
            block.end_class = EndClass::Exit;
        } else {
            UNREACHABLE();
        }
    }
}

void CFG::RemoveUnreachableBlocks() {
    for (auto it = std::next(blocks.begin()); it != blocks.end();) {
        if (it->num_predecessors == 0) {
            LOG_WARNING(Render_Recompiler, "Removing unreachable block begin={:#x}", it->begin);
            it = blocks.erase(it);
        } else {
            it++;
        }
    }
}

std::string CFG::Dot() const {
    int node_uid{0};

    const auto name_of = [](const Block& block) { return fmt::format("\"{:#x}\"", block.begin); };

    std::string dot{"digraph shader {\n"};
    dot += fmt::format("\tsubgraph cluster_{} {{\n", 0);
    dot += fmt::format("\t\tnode [style=filled];\n");
    for (const Block& block : blocks) {
        const std::string name{name_of(block)};
        const auto add_branch = [&](Block* branch, bool add_label) {
            dot += fmt::format("\t\t{}->{}", name, name_of(*branch));
            if (add_label && block.cond != IR::Condition::True &&
                block.cond != IR::Condition::False) {
                dot += fmt::format(" [label=\"{}\"]", block.cond);
            }
            dot += '\n';
        };
        dot += fmt::format("\t\t{};\n", name);
        switch (block.end_class) {
        case EndClass::Branch:
            if (block.cond != IR::Condition::False) {
                add_branch(block.branch_true, true);
            }
            if (block.cond != IR::Condition::True) {
                add_branch(block.branch_false, false);
            }
            break;
        case EndClass::Exit:
            dot += fmt::format("\t\t{}->N{};\n", name, node_uid);
            dot +=
                fmt::format("\t\tN{} [label=\"Exit\"][shape=square][style=stripped];\n", node_uid);
            ++node_uid;
            break;
        }
    }
    dot += "\t\tlabel = \"main\";\n\t}\n";
    if (blocks.empty()) {
        dot += "Start;\n";
    } else {
        dot += fmt::format("\tStart -> {};\n", name_of(*blocks.begin()));
    }
    dot += fmt::format("\tStart [shape=diamond];\n");
    dot += "}\n";
    return dot;
}

} // namespace Shader::Gcn
