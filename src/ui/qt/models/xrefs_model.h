#pragma once

#include <QAbstractTableModel>
#include <vector>
#include "core/analyzer.h"

class XrefsModel : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Mode { Callers, Callees };

    explicit XrefsModel(QObject* parent = nullptr);

    void setXrefs(const std::vector<atlus::XRef>& xrefs, Mode mode);
    void clear();

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

private:
    std::vector<atlus::XRef> m_xrefs;
    Mode m_mode = Callers;
};
