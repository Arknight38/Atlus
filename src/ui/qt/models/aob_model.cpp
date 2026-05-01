#include "aob_model.h"

AobModel::AobModel(QObject* parent)
    : QAbstractTableModel(parent)
{
}

void AobModel::setSignatures(const std::vector<atlus::AobSignature>& signatures)
{
    beginResetModel();
    m_signatures = signatures;
    endResetModel();
}

void AobModel::clear()
{
    beginResetModel();
    m_signatures.clear();
    endResetModel();
}

int AobModel::rowCount(const QModelIndex&) const
{
    return static_cast<int>(m_signatures.size());
}

int AobModel::columnCount(const QModelIndex&) const
{
    return 3; // Offset, IDA, Cheat Engine
}

QVariant AobModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() >= static_cast<int>(m_signatures.size()))
        return QVariant();

    const auto& sig = m_signatures[static_cast<size_t>(index.row())];

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
            case 0: return QString("0x%1").arg(sig.offset, 0, 16);
            case 1: return QString::fromStdString(sig.ida_style);
            case 2: return QString::fromStdString(sig.ce_style);
            default: return QVariant();
        }
    }

    if (role == Qt::TextAlignmentRole) {
        if (index.column() == 0) return Qt::AlignRight;
        return Qt::AlignLeft;
    }

    return QVariant();
}

QVariant AobModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        return QVariant();

    switch (section) {
        case 0: return QStringLiteral("Offset");
        case 1: return QStringLiteral("IDA Style");
        case 2: return QStringLiteral("CE Style");
        default: return QVariant();
    }
}
