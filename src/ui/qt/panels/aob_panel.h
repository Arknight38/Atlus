#pragma once

#include <QWidget>
#include "models/aob_model.h"

QT_BEGIN_NAMESPACE
class QTableView;
QT_END_NAMESPACE

class AobPanel : public QWidget {
    Q_OBJECT
public:
    explicit AobPanel(QWidget* parent = nullptr);

    void setSignatures(const std::vector<atlus::AobSignature>& signatures);
    void clear();

private:
    AobModel* m_model = nullptr;
    QTableView* m_view = nullptr;
};
