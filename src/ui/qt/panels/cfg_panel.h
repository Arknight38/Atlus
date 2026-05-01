#pragma once

#include <QWidget>

QT_BEGIN_NAMESPACE
class QPlainTextEdit;
class QPushButton;
class QLabel;
QT_END_NAMESPACE

class CFGPanel : public QWidget {
    Q_OBJECT
public:
    explicit CFGPanel(QWidget* parent = nullptr);

    void setCFG(const QString& yaml, uint64_t address);
    void setStatus(const QString& status);
    void clear();

    uint64_t currentAddress() const { return m_currentAddress; }

signals:
    void requestCFG(uint64_t address);
    void cfgNodeSelected(uint64_t address);

private slots:
    void onRefreshClicked();

private:
    QPlainTextEdit* m_editor = nullptr;
    QLabel* m_statusLabel = nullptr;
    QPushButton* m_refreshBtn = nullptr;
    uint64_t m_currentAddress = 0;
};
