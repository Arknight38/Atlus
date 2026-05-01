#pragma once

#include <QWidget>

QT_BEGIN_NAMESPACE
class QTextBrowser;
class QPushButton;
class QLabel;
QT_END_NAMESPACE

class CallGraphPanel : public QWidget {
    Q_OBJECT
public:
    explicit CallGraphPanel(QWidget* parent = nullptr);

    void setSVG(const QString& svg);
    void setStatus(const QString& status);
    void clear();

signals:
    void requestCallGraph();

private slots:
    void onRefreshClicked();
    void onSaveClicked();

private:
    QTextBrowser* m_viewer = nullptr;
    QLabel* m_statusLabel = nullptr;
    QPushButton* m_refreshBtn = nullptr;
    QPushButton* m_saveBtn = nullptr;
    QString m_currentSVG;
};
