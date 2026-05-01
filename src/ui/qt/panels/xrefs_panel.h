#pragma once

#include <QWidget>
#include "models/xrefs_model.h"

QT_BEGIN_NAMESPACE
class QTableView;
class QTabWidget;
QT_END_NAMESPACE

class XrefsPanel : public QWidget {
    Q_OBJECT
public:
    explicit XrefsPanel(QWidget* parent = nullptr);

    void setCallers(const std::vector<atlus::XRef>& xrefs);
    void setCallees(const std::vector<atlus::XRef>& xrefs);
    void clear();

signals:
    void xrefSelected(uint64_t address);

private:
    XrefsModel* m_callersModel = nullptr;
    XrefsModel* m_calleesModel = nullptr;
    QTableView* m_callersView = nullptr;
    QTableView* m_calleesView = nullptr;
};
