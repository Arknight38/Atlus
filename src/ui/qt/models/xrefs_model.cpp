#include "xrefs_model.h"

XrefsModel::XrefsModel(QObject* parent)
    : QAbstractTableModel(parent)
{
}

void XrefsModel::setXrefs(const std::vector<atlus::XRef>& xrefs, Mode mode)
{
    beginResetModel();
    m_xrefs = xrefs;
    m_mode = mode;
    endResetModel();
}

void XrefsModel::clear()
{
    beginResetModel();
    m_xrefs.clear();
    endResetModel();
}

int XrefsModel::rowCount(const QModelIndex&) const
{
    return static_cast<int>(m_xrefs.size());
}

int XrefsModel::columnCount(const QModelIndex&) const
{
    return 3; // Address, Target, Type
}

QVariant XrefsModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() >= static_cast<int>(m_xrefs.size()))
        return QVariant();

    const auto& xr = m_xrefs[static_cast<size_t>(index.row())];

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
            case 0:
                if (m_mode == Callers)
                    return QString("0x%1").arg(xr.from_address, 0, 16);
                else
                    return QString("0x%1").arg(xr.to_address, 0, 16);
            case 1:
                if (m_mode == Callers)
                    return QString("0x%1").arg(xr.to_address, 0, 16);
                else
                    return QString("0x%1").arg(xr.from_address, 0, 16);
            case 2:
                return xr.is_call ? QStringLiteral("CALL") : QStringLiteral("JMP");
            default:
                return QVariant();
        }
    }

    if (role == Qt::TextAlignmentRole)
        return Qt::AlignRight;

    return QVariant();
}

QVariant XrefsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        return QVariant();

    if (m_mode == Callers) {
        switch (section) {
            case 0: return QStringLiteral("Caller");
            case 1: return QStringLiteral("Target");
            case 2: return QStringLiteral("Type");
        }
    } else {
        switch (section) {
            case 0: return QStringLiteral("Callee");
            case 1: return QStringLiteral("From");
            case 2: return QStringLiteral("Type");
        }
    }
    return QVariant();
}
