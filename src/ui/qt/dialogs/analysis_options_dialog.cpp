#include "analysis_options_dialog.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QCheckBox>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QDialogButtonBox>
#include <QFileDialog>

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisOptions persistence
// ─────────────────────────────────────────────────────────────────────────────

void AnalysisOptions::load(QSettings& s)
{
    // Basic analysis
    scanFunctions      = s.value("analysis/scanFunctions",      true).toBool();
    analyzeXRefs       = s.value("analysis/analyzeXRefs",       true).toBool();
    analyzeImports     = s.value("analysis/analyzeImports",     true).toBool();
    generateSignatures = s.value("analysis/generateSignatures", false).toBool();

    // rev.ng integration
    enableRevng        = s.value("analysis/enableRevng",        false).toBool();
    revngPath          = s.value("revngPath",                   QString()).toString();

    // rev.ng advanced features
    revngEmitCFG        = s.value("analysis/revngEmitCFG",        true).toBool();
    revngRenderCallGraph = s.value("analysis/revngRenderCallGraph", true).toBool();
    revngABIDetection   = s.value("analysis/revngABIDetection",   true).toBool();
    revngDataLayout     = s.value("analysis/revngDataLayout",     true).toBool();
    revngCrossXRefs     = s.value("analysis/revngCrossXRefs",     true).toBool();
}

void AnalysisOptions::save(QSettings& s) const
{
    // Basic analysis
    s.setValue("analysis/scanFunctions",      scanFunctions);
    s.setValue("analysis/analyzeXRefs",       analyzeXRefs);
    s.setValue("analysis/analyzeImports",     analyzeImports);
    s.setValue("analysis/generateSignatures", generateSignatures);

    // rev.ng integration
    s.setValue("analysis/enableRevng",        enableRevng);
    s.setValue("revngPath",                   revngPath);

    // rev.ng advanced features
    s.setValue("analysis/revngEmitCFG",        revngEmitCFG);
    s.setValue("analysis/revngRenderCallGraph", revngRenderCallGraph);
    s.setValue("analysis/revngABIDetection",   revngABIDetection);
    s.setValue("analysis/revngDataLayout",     revngDataLayout);
    s.setValue("analysis/revngCrossXRefs",     revngCrossXRefs);
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisOptionsDialog
// ─────────────────────────────────────────────────────────────────────────────

AnalysisOptionsDialog::AnalysisOptionsDialog(const AnalysisOptions& current, QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle("Analysis Options");
    setMinimumWidth(500);

    auto* layout = new QVBoxLayout(this);
    layout->setSpacing(10);
    layout->setContentsMargins(12, 12, 12, 12);

    // ── Analysis Passes ──────────────────────────────────────────────────────

    auto* passesBox    = new QGroupBox("Analysis Passes", this);
    auto* passesLayout = new QVBoxLayout(passesBox);
    passesLayout->setSpacing(5);

    m_scanFunctionsCheck = new QCheckBox("Function Scanning  (prologue-based detection)", passesBox);
    m_scanFunctionsCheck->setChecked(current.scanFunctions);
    passesLayout->addWidget(m_scanFunctionsCheck);

    m_analyzeXRefsCheck = new QCheckBox("Cross-reference Analysis", passesBox);
    m_analyzeXRefsCheck->setChecked(current.analyzeXRefs);
    passesLayout->addWidget(m_analyzeXRefsCheck);

    m_analyzeImportsCheck = new QCheckBox("Import / Export Analysis", passesBox);
    m_analyzeImportsCheck->setChecked(current.analyzeImports);
    passesLayout->addWidget(m_analyzeImportsCheck);

    m_genSigsCheck = new QCheckBox("AOB Signature Generation  (slow, optional)", passesBox);
    m_genSigsCheck->setChecked(current.generateSignatures);
    passesLayout->addWidget(m_genSigsCheck);

    layout->addWidget(passesBox);

    // ── Decompiler ────────────────────────────────────────────────────────────

    auto* decompBox    = new QGroupBox("Decompiler", this);
    auto* decompLayout = new QVBoxLayout(decompBox);
    decompLayout->setSpacing(5);

    m_enableRevngCheck = new QCheckBox(
        "Enable rev.ng decompilation  (requires WSL2 or Docker on Windows)", decompBox);
    m_enableRevngCheck->setChecked(current.enableRevng);
    decompLayout->addWidget(m_enableRevngCheck);

    auto* pathLayout = new QHBoxLayout();
    pathLayout->addWidget(new QLabel("rev.ng path:", decompBox));
    m_revngPathEdit = new QLineEdit(current.revngPath, decompBox);
    m_revngPathEdit->setPlaceholderText("Leave empty for WSL / Docker auto-detect");
    m_revngPathEdit->setEnabled(current.enableRevng);
    pathLayout->addWidget(m_revngPathEdit);
    m_revngBrowseBtn = new QPushButton("Browse...", decompBox);
    m_revngBrowseBtn->setEnabled(current.enableRevng);
    m_revngBrowseBtn->setFixedWidth(80);
    pathLayout->addWidget(m_revngBrowseBtn);
    decompLayout->addLayout(pathLayout);

    // ── rev.ng Advanced Features ────────────────────────────────────────────
    decompLayout->addSpacing(10);
    auto* advancedLabel = new QLabel("<b>rev.ng Advanced Features:</b>", decompBox);
    decompLayout->addWidget(advancedLabel);

    m_revngEmitCFGCheck = new QCheckBox(
        "Emit Control Flow Graph (CFG) as YAML  (emit-cfg)", decompBox);
    m_revngEmitCFGCheck->setChecked(current.revngEmitCFG);
    m_revngEmitCFGCheck->setEnabled(current.enableRevng);
    decompLayout->addWidget(m_revngEmitCFGCheck);

    m_revngRenderCallGraphCheck = new QCheckBox(
        "Render Call Graph as SVG  (render-svg-call-graph)", decompBox);
    m_revngRenderCallGraphCheck->setChecked(current.revngRenderCallGraph);
    m_revngRenderCallGraphCheck->setEnabled(current.enableRevng);
    decompLayout->addWidget(m_revngRenderCallGraphCheck);

    m_revngABIDetectionCheck = new QCheckBox(
        "ABI Detection and Calling Convention Recovery  (detect-abi)", decompBox);
    m_revngABIDetectionCheck->setChecked(current.revngABIDetection);
    m_revngABIDetectionCheck->setEnabled(current.enableRevng);
    decompLayout->addWidget(m_revngABIDetectionCheck);

    m_revngDataLayoutCheck = new QCheckBox(
        "Data Layout Analysis and Struct Recovery", decompBox);
    m_revngDataLayoutCheck->setChecked(current.revngDataLayout);
    m_revngDataLayoutCheck->setEnabled(current.enableRevng);
    decompLayout->addWidget(m_revngDataLayoutCheck);

    m_revngCrossXRefsCheck = new QCheckBox(
        "Cross-references Across Whole Binary  (enhanced xrefs)", decompBox);
    m_revngCrossXRefsCheck->setChecked(current.revngCrossXRefs);
    m_revngCrossXRefsCheck->setEnabled(current.enableRevng);
    decompLayout->addWidget(m_revngCrossXRefsCheck);

    layout->addWidget(decompBox);
    layout->addStretch();

    // ── Buttons ───────────────────────────────────────────────────────────────

    auto* btnLayout   = new QHBoxLayout();
    auto* defaultsBtn = new QPushButton("Defaults", this);
    defaultsBtn->setFixedWidth(80);
    btnLayout->addWidget(defaultsBtn);
    btnLayout->addStretch();

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    btnLayout->addWidget(buttons);
    layout->addLayout(btnLayout);

    connect(m_enableRevngCheck, &QCheckBox::toggled,
            this, &AnalysisOptionsDialog::onRevngToggled);
    connect(m_revngBrowseBtn, &QPushButton::clicked,
            this, &AnalysisOptionsDialog::browseRevngPath);
    connect(defaultsBtn, &QPushButton::clicked,
            this, &AnalysisOptionsDialog::resetDefaults);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

AnalysisOptions AnalysisOptionsDialog::options() const
{
    AnalysisOptions o;
    // Basic analysis
    o.scanFunctions      = m_scanFunctionsCheck->isChecked();
    o.analyzeXRefs       = m_analyzeXRefsCheck->isChecked();
    o.analyzeImports     = m_analyzeImportsCheck->isChecked();
    o.generateSignatures = m_genSigsCheck->isChecked();

    // rev.ng integration
    o.enableRevng        = m_enableRevngCheck->isChecked();
    o.revngPath          = m_revngPathEdit->text();

    // rev.ng advanced features
    o.revngEmitCFG        = m_revngEmitCFGCheck->isChecked();
    o.revngRenderCallGraph = m_revngRenderCallGraphCheck->isChecked();
    o.revngABIDetection   = m_revngABIDetectionCheck->isChecked();
    o.revngDataLayout     = m_revngDataLayoutCheck->isChecked();
    o.revngCrossXRefs     = m_revngCrossXRefsCheck->isChecked();

    return o;
}

void AnalysisOptionsDialog::onRevngToggled(bool enabled)
{
    m_revngPathEdit->setEnabled(enabled);
    m_revngBrowseBtn->setEnabled(enabled);
    m_revngEmitCFGCheck->setEnabled(enabled);
    m_revngRenderCallGraphCheck->setEnabled(enabled);
    m_revngABIDetectionCheck->setEnabled(enabled);
    m_revngDataLayoutCheck->setEnabled(enabled);
    m_revngCrossXRefsCheck->setEnabled(enabled);
}

void AnalysisOptionsDialog::browseRevngPath()
{
    QString path = QFileDialog::getOpenFileName(
        this, "Locate rev.ng binary", m_revngPathEdit->text(),
        "Executables (*.exe *.cmd);;All files (*)");
    if (!path.isEmpty())
        m_revngPathEdit->setText(path);
}

void AnalysisOptionsDialog::resetDefaults()
{
    // Basic analysis
    m_scanFunctionsCheck->setChecked(true);
    m_analyzeXRefsCheck->setChecked(true);
    m_analyzeImportsCheck->setChecked(true);
    m_genSigsCheck->setChecked(false);

    // rev.ng integration
    m_enableRevngCheck->setChecked(false);

    // rev.ng advanced features
    m_revngEmitCFGCheck->setChecked(true);
    m_revngRenderCallGraphCheck->setChecked(true);
    m_revngABIDetectionCheck->setChecked(true);
    m_revngDataLayoutCheck->setChecked(true);
    m_revngCrossXRefsCheck->setChecked(true);
}
