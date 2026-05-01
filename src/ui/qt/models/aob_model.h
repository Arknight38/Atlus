#pragma once

#include <QAbstractTableModel>
#include <vector>
#include "core/pattern_scanner.h"

class AobModel : public QAbstractTableModel {
    Q_OBJECT

public:
    explicit AobModel(QObject* parent = nullptr);

    void setSignatures(const std::vector<atlus::AobSignature>& signatures);
    void clear();

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

private:
    std::vector<atlus::AobSignature> m_signatures;
};
