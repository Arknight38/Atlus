#pragma once

#include <QAbstractTableModel>
#include <vector>
#include "core/analyzer.h"

class FunctionsModel : public QAbstractTableModel {
    Q_OBJECT

public:
    explicit FunctionsModel(QObject* parent = nullptr);

    void setData(const std::vector<atlus::Function>& functions);
    void clear();
    const atlus::Function* functionAt(int row) const;

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

private:
    std::vector<atlus::Function> m_functions;
};
