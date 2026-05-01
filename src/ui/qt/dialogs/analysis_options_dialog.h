#pragma once

#include <QDialog>
#include <QSettings>

QT_BEGIN_NAMESPACE
class QCheckBox;
class QGroupBox;
class QLineEdit;
class QPushButton;
QT_END_NAMESPACE

struct AnalysisOptions {
    // Basic analysis
    bool scanFunctions      = true;
    bool analyzeXRefs       = true;
    bool analyzeImports     = true;
    bool generateSignatures = false;

    // rev.ng integration
    bool enableRevng        = false;
    QString revngPath;

    // rev.ng advanced features
    bool revngEmitCFG       = true;   // emit-cfg: Control Flow Graph as YAML
    bool revngRenderCallGraph = true; // render-svg-call-graph: Call graph as SVG
    bool revngABIDetection  = true;   // detect-abi: ABI and calling convention
    bool revngDataLayout    = true;   // Data layout analysis and struct recovery
    bool revngCrossXRefs    = true;   // Cross-references across whole binary

    void load(QSettings& s);
    void save(QSettings& s) const;
};

class AnalysisOptionsDialog : public QDialog {
    Q_OBJECT

public:
    explicit AnalysisOptionsDialog(const AnalysisOptions& current, QWidget* parent = nullptr);

    AnalysisOptions options() const;

private slots:
    void onRevngToggled(bool enabled);
    void browseRevngPath();
    void resetDefaults();

private:
    // Basic analysis
    QCheckBox*   m_scanFunctionsCheck  = nullptr;
    QCheckBox*   m_analyzeXRefsCheck   = nullptr;
    QCheckBox*   m_analyzeImportsCheck = nullptr;
    QCheckBox*   m_genSigsCheck        = nullptr;

    // rev.ng basic
    QCheckBox*   m_enableRevngCheck    = nullptr;
    QLineEdit*   m_revngPathEdit       = nullptr;
    QPushButton* m_revngBrowseBtn      = nullptr;

    // rev.ng advanced features
    QCheckBox*   m_revngEmitCFGCheck       = nullptr;
    QCheckBox*   m_revngRenderCallGraphCheck = nullptr;
    QCheckBox*   m_revngABIDetectionCheck  = nullptr;
    QCheckBox*   m_revngDataLayoutCheck    = nullptr;
    QCheckBox*   m_revngCrossXRefsCheck    = nullptr;
};
