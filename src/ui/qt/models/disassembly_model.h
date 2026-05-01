#pragma once

#include <QAbstractTableModel>
#include <vector>
#include "core/disassembler.h"

class DisassemblyModel : public QAbstractTableModel {
    Q_OBJECT

public:
    explicit DisassemblyModel(QObject* parent = nullptr);

    void setInstructions(const std::vector<atlus::Instruction>& instructions);
    void clear();
    const atlus::Instruction* instructionAt(int row) const;

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

private:
    std::vector<atlus::Instruction> m_instructions;
};
