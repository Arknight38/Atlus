#include "functions_model.h"
#include <cstdint>

FunctionsModel::FunctionsModel(QObject* parent)
    : QAbstractTableModel(parent)
{
}

void FunctionsModel::setData(const std::vector<atlus::Function>& functions)
{
    beginResetModel();
    m_functions = functions;
    endResetModel();
}

void FunctionsModel::clear()
{
    beginResetModel();
    m_functions.clear();
    endResetModel();
}

const atlus::Function* FunctionsModel::functionAt(int row) const
{
    if (row < 0 || row >= static_cast<int>(m_functions.size()))
        return nullptr;
    return &m_functions[static_cast<size_t>(row)];
}

int FunctionsModel::rowCount(const QModelIndex&) const
{
    return static_cast<int>(m_functions.size());
}

int FunctionsModel::columnCount(const QModelIndex&) const
{
    return 4; // Name, Start, End, Size
}

QVariant FunctionsModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() >= static_cast<int>(m_functions.size()))
        return QVariant();

    const auto& fn = m_functions[static_cast<size_t>(index.row())];

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
            case 0: return QString::fromStdString(fn.name);
            case 1: return QString("0x%1").arg(fn.start_address, 0, 16);
            case 2: return QString("0x%1").arg(fn.end_address, 0, 16);
            case 3: return QString::number(fn.size_bytes);
            default: return QVariant();
        }
    }

    if (role == Qt::TextAlignmentRole) {
        if (index.column() == 0) return Qt::AlignLeft;
        return Qt::AlignRight;
    }

    return QVariant();
}

QVariant FunctionsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        return QVariant();

    switch (section) {
        case 0: return QStringLiteral("Name");
        case 1: return QStringLiteral("Start");
        case 2: return QStringLiteral("End");
        case 3: return QStringLiteral("Size");
        default: return QVariant();
    }
}
