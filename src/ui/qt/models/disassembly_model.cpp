#include "disassembly_model.h"

DisassemblyModel::DisassemblyModel(QObject* parent)
    : QAbstractTableModel(parent)
{
}

void DisassemblyModel::setInstructions(const std::vector<atlus::Instruction>& instructions)
{
    beginResetModel();
    m_instructions = instructions;
    endResetModel();
}

void DisassemblyModel::clear()
{
    beginResetModel();
    m_instructions.clear();
    endResetModel();
}

const atlus::Instruction* DisassemblyModel::instructionAt(int row) const
{
    if (row < 0 || row >= static_cast<int>(m_instructions.size()))
        return nullptr;
    return &m_instructions[static_cast<size_t>(row)];
}

int DisassemblyModel::rowCount(const QModelIndex&) const
{
    return static_cast<int>(m_instructions.size());
}

int DisassemblyModel::columnCount(const QModelIndex&) const
{
    return 4; // Address, Bytes, Mnemonic, Operands
}

QVariant DisassemblyModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() >= static_cast<int>(m_instructions.size()))
        return QVariant();

    const auto& ins = m_instructions[static_cast<size_t>(index.row())];

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
            case 0: return QString("0x%1").arg(ins.address, 0, 16);
            case 1: {
                QString bytes;
                for (auto b : ins.bytes)
                    bytes += QString("%1 ").arg(b, 2, 16, QLatin1Char('0'));
                return bytes.trimmed();
            }
            case 2: return QString::fromStdString(ins.mnemonic);
            case 3: return QString::fromStdString(ins.operands);
            default: return QVariant();
        }
    }

    if (role == Qt::TextAlignmentRole) {
        if (index.column() == 0) return Qt::AlignRight;
        if (index.column() == 1) return Qt::AlignLeft;
        return Qt::AlignLeft;
    }

    return QVariant();
}

QVariant DisassemblyModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        return QVariant();

    switch (section) {
        case 0: return QStringLiteral("Address");
        case 1: return QStringLiteral("Bytes");
        case 2: return QStringLiteral("Mnemonic");
        case 3: return QStringLiteral("Operands");
        default: return QVariant();
    }
}
