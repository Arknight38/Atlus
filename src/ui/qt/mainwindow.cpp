#include "mainwindow.h"

#include <QApplication>
#include <QMenuBar>
#include <QStatusBar>
#include <QProgressBar>
#include <QLabel>
#include <QDockWidget>
#include <QFileDialog>
#include <QMessageBox>
#include <QShortcut>
#include <QKeySequence>
#include <QTextEdit>
#include <QSettings>
#include <QtConcurrent/QtConcurrent>
#include <QFutureWatcher>
#include <QFont>
#include <QThreadPool>
#include <QTabWidget>
#include <QTimer>

#include "theme.h"
#include "core/loader.h"
#include "core/pe_parser.h"
#include "core/analyzer.h"
#include "panels/functions_panel.h"
#include "panels/sections_panel.h"
#include "panels/imports_panel.h"
#include "panels/hex_panel.h"
#include "panels/disassembly_panel.h"
#include "panels/pseudocode_panel.h"
#include "panels/xrefs_panel.h"
#include "panels/aob_panel.h"
#include "panels/cfg_panel.h"
#include "panels/callgraph_panel.h"
#include "decompiler_worker.h"
#include "dialogs/settings_dialog.h"

struct AnalysisResult {
    bool success = false;
    QString message;
    atlus::BinaryFile binary;
    atlus::PEInfo pe;
    std::vector<atlus::Function> functions;
};

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle("Atlus");
    resize(1600, 1000);

    Theme::applyToApplication();
    setupMenuBar();
    setupStatusBar();
    setupDockAreas();
    setupPanels();

    // Load persisted settings
    QSettings settings("Atlus", "Atlus");
    AppSettings appSettings;
    appSettings.load(settings);
    if (appSettings.fontSize <= 0) appSettings.fontSize = 10;
    applyFontSize(appSettings.fontSize);
    m_analysisOptions.load(settings);
    m_enableRevngAct->setChecked(m_analysisOptions.enableRevng);
    m_reanalyzeAct->setEnabled(false);

    // Propagate settings to workers
    if (m_revngWorker) {
        if (!m_analysisOptions.revngPath.isEmpty())
            m_revngWorker->setPath(m_analysisOptions.revngPath);
        m_revngWorker->setAnalysisOptions(m_analysisOptions);
    }
    if (m_analysisWorker) {
        if (!m_analysisOptions.revngPath.isEmpty())
            m_analysisWorker->setPath(m_analysisOptions.revngPath);
        m_analysisWorker->setAnalysisOptions(m_analysisOptions);
    }

    appendLog("Atlus Qt6 UI loaded.");

    // Keyboard shortcuts
    new QShortcut(QKeySequence("Ctrl+O"), this, [this]() { onFileOpen(); });
    new QShortcut(QKeySequence("Ctrl+Q"), this, qApp, &QApplication::quit);
}

MainWindow::~MainWindow()
{
    if (m_revngThread) {
        m_revngThread->quit();
        m_revngThread->wait(3000);
        if (m_revngThread->isRunning()) {
            m_revngThread->terminate();
            m_revngThread->wait(1000);
        }
    }
    if (m_analysisThread) {
        m_analysisThread->quit();
        m_analysisThread->wait(3000);
        if (m_analysisThread->isRunning()) {
            m_analysisThread->terminate();
            m_analysisThread->wait(1000);
        }
    }
}

void MainWindow::setupMenuBar()
{
    // File menu
    m_fileMenu = menuBar()->addMenu("&File");
    m_openAct = m_fileMenu->addAction("&Open...");
    m_openAct->setShortcut(QKeySequence::Open);
    connect(m_openAct, &QAction::triggered, this, &MainWindow::onFileOpen);
    m_openDiffAct = m_fileMenu->addAction("Open &Diff...");
    connect(m_openDiffAct, &QAction::triggered, this, &MainWindow::onFileOpenDiff);

    m_recentMenu = m_fileMenu->addMenu("Open &Recent");
    populateRecentMenu();

    m_fileMenu->addSeparator();
    m_settingsAct = m_fileMenu->addAction("&Settings...");
    m_settingsAct->setShortcut(QKeySequence("Ctrl+,"));
    connect(m_settingsAct, &QAction::triggered, this, &MainWindow::onSettings);
    m_fileMenu->addSeparator();
    m_exitAct = m_fileMenu->addAction("E&xit");
    m_exitAct->setShortcut(QKeySequence::Quit);
    connect(m_exitAct, &QAction::triggered, qApp, &QApplication::quit);

    // View menu
    m_viewMenu = menuBar()->addMenu("&View");

    // Analysis menu
    setupAnalysisMenu();

    // Help menu
    m_helpMenu = menuBar()->addMenu("&Help");
    m_helpMenu->addAction("&About", this, []() {
        QMessageBox::about(nullptr, "About Atlus",
            "<h2>Atlus</h2>"
            "<p>A cross-platform reverse engineering framework.</p>"
            "<p>Qt6 UI migration in progress.</p>");
    });
}

void MainWindow::setupStatusBar()
{
    // Left: general status
    m_statusLabel = new QLabel("Ready", this);
    statusBar()->addWidget(m_statusLabel, 1);

    // Center: analysis stage indicator (for rev.ng progress)
    m_analysisStageLabel = new QLabel("", this);
    m_analysisStageLabel->setStyleSheet("color: #2196F3; padding: 0 10px;");
    m_analysisStageLabel->setVisible(false);
    statusBar()->addWidget(m_analysisStageLabel);

    // Right: progress bar
    m_progressBar = new QProgressBar(this);
    m_progressBar->setMaximumWidth(200);
    m_progressBar->setRange(0, 0); // indeterminate
    m_progressBar->setVisible(false);
    statusBar()->addPermanentWidget(m_progressBar);
}

void MainWindow::setupDockAreas()
{
    setDockNestingEnabled(true);
    setCorner(Qt::TopLeftCorner, Qt::LeftDockWidgetArea);
    setCorner(Qt::BottomLeftCorner, Qt::LeftDockWidgetArea);
    setCorner(Qt::TopRightCorner, Qt::RightDockWidgetArea);
    setCorner(Qt::BottomRightCorner, Qt::RightDockWidgetArea);
}

static QDockWidget* createDock(QWidget* parent, const QString& title, QWidget* widget)
{
    auto* dock = new QDockWidget(title, parent);
    dock->setWidget(widget);
    dock->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetFloatable | QDockWidget::DockWidgetClosable);
    return dock;
}

void MainWindow::setupPanels()
{
    // --- Central working area (Disassembly + Pseudocode) ---
    m_centralTabs = new QTabWidget(this);
    m_centralTabs->setDocumentMode(true);

    m_disasmPanel = new DisassemblyPanel(this);
    connect(m_disasmPanel, &DisassemblyPanel::instructionSelected,
            this, &MainWindow::onInstructionSelected);
    m_centralTabs->addTab(m_disasmPanel, "Disassembly");

    m_pseudoPanel = new PseudocodePanel(this);
    m_centralTabs->addTab(m_pseudoPanel, "Pseudocode");

    // CFG tab for control flow graph
    m_cfgPanel = new CFGPanel(this);
    connect(m_cfgPanel, &CFGPanel::requestCFG, this, &MainWindow::requestCFG);
    m_centralTabs->addTab(m_cfgPanel, "CFG");

    setCentralWidget(m_centralTabs);

    // --- Left dock area: Functions (dominant), Sections + Imports tabified ---
    m_functionsPanel = new FunctionsPanel(this);
    connect(m_functionsPanel, &FunctionsPanel::functionSelected,
            this, &MainWindow::onFunctionSelected);
    auto* fnDock = createDock(this, "Functions", m_functionsPanel);
    addDockWidget(Qt::LeftDockWidgetArea, fnDock);

    m_sectionsPanel = new SectionsPanel(this);
    auto* secDock = createDock(this, "Sections", m_sectionsPanel);
    addDockWidget(Qt::LeftDockWidgetArea, secDock);

    m_importsPanel = new ImportsPanel(this);
    auto* impDock = createDock(this, "Imports", m_importsPanel);
    addDockWidget(Qt::LeftDockWidgetArea, impDock);
    tabifyDockWidget(secDock, impDock);
    secDock->raise();

    // --- Right dock area: Hex ---
    m_hexPanel = new HexPanel(this);
    auto* hexDock = createDock(this, "Hex View", m_hexPanel);
    addDockWidget(Qt::RightDockWidgetArea, hexDock);

    // --- Bottom dock area: Output, XRefs, AOB ---
    m_logPanel = new QTextEdit(this);
    m_logPanel->setReadOnly(true);
    auto* logDock = createDock(this, "Output", m_logPanel);
    addDockWidget(Qt::BottomDockWidgetArea, logDock);

    m_xrefsPanel = new XrefsPanel(this);
    connect(m_xrefsPanel, &XrefsPanel::xrefSelected,
            this, &MainWindow::onXrefSelected);
    auto* xrefDock = createDock(this, "XRefs", m_xrefsPanel);
    addDockWidget(Qt::BottomDockWidgetArea, xrefDock);

    m_aobPanel = new AobPanel(this);
    auto* aobDock = createDock(this, "AOB Signatures", m_aobPanel);
    addDockWidget(Qt::BottomDockWidgetArea, aobDock);

    // Call Graph panel in bottom dock area
    m_callGraphPanel = new CallGraphPanel(this);
    connect(m_callGraphPanel, &CallGraphPanel::requestCallGraph, this, &MainWindow::requestCallGraph);
    auto* callGraphDock = createDock(this, "Call Graph", m_callGraphPanel);
    addDockWidget(Qt::BottomDockWidgetArea, callGraphDock);

    tabifyDockWidget(logDock, xrefDock);
    tabifyDockWidget(logDock, aobDock);
    tabifyDockWidget(logDock, callGraphDock);
    logDock->raise();

    // View menu toggles
    auto addDockToggle = [this](QDockWidget* dock) {
        auto* act = m_viewMenu->addAction(dock->windowTitle());
        act->setCheckable(true);
        act->setChecked(true);
        act->setData(QVariant::fromValue(dock));
        connect(act, &QAction::triggered, this, &MainWindow::onToggleDock);
        connect(dock, &QDockWidget::visibilityChanged, act, [act](bool visible) {
            act->setChecked(visible);
        });
    };
    addDockToggle(fnDock);
    addDockToggle(secDock);
    addDockToggle(impDock);
    addDockToggle(hexDock);
    addDockToggle(logDock);
    addDockToggle(xrefDock);
    addDockToggle(aobDock);
    addDockToggle(callGraphDock);

    // Constrain initial dock sizes so the central area dominates
    resizeDocks({fnDock, secDock, impDock}, {260, 260, 260}, Qt::Horizontal);
    resizeDocks({hexDock}, {420}, Qt::Horizontal);
    resizeDocks({logDock, xrefDock, aobDock, callGraphDock}, {140, 140, 140, 140}, Qt::Vertical);

    // Decompiler worker thread (for function decompilation)
    m_revngThread = new QThread(this);
    m_revngWorker = new RevngWorker();
    m_revngWorker->moveToThread(m_revngThread);

    connect(m_revngThread, &QThread::started,
            m_revngWorker, &RevngWorker::init);
    connect(m_revngWorker, &RevngWorker::decompileReady,
            this, &MainWindow::onPseudocodeReady);
    connect(m_revngWorker, &RevngWorker::decompileError,
            this, &MainWindow::onDecompileError);
    connect(m_revngWorker, &RevngWorker::analysisStageChanged,
            this, &MainWindow::onAnalysisStageChanged);
    connect(this, &MainWindow::requestDecompile,
            m_revngWorker, &RevngWorker::decompile);
    connect(m_revngWorker, &RevngWorker::stateChanged,
            this, &MainWindow::onDecompilerState);
    connect(m_revngWorker, &RevngWorker::progressOutput,
            this, &MainWindow::appendLog);

    m_revngThread->start();

    // Analysis worker thread (for CFG and call graph - runs in parallel)
    m_analysisThread = new QThread(this);
    m_analysisWorker = new RevngWorker();
    m_analysisWorker->moveToThread(m_analysisThread);

    connect(m_analysisThread, &QThread::started,
            m_analysisWorker, &RevngWorker::init);
    connect(m_analysisWorker, &RevngWorker::cfgReady,
            this, &MainWindow::onCFGReady);
    connect(m_analysisWorker, &RevngWorker::cfgError,
            this, &MainWindow::onCFGError);
    connect(m_analysisWorker, &RevngWorker::callGraphReady,
            this, &MainWindow::onCallGraphReady);
    connect(m_analysisWorker, &RevngWorker::callGraphError,
            this, &MainWindow::onCallGraphError);
    connect(this, &MainWindow::requestCFGGeneration,
            m_analysisWorker, &RevngWorker::generateCFG);
    connect(this, &MainWindow::requestCallGraphGeneration,
            m_analysisWorker, &RevngWorker::generateCallGraph);
    connect(m_analysisWorker, &RevngWorker::progressOutput,
            this, &MainWindow::appendLog);

    m_analysisThread->start();
}

void MainWindow::runAnalysis(const QString& path)
{
    auto* watcher = new QFutureWatcher<AnalysisResult>(this);
    connect(watcher, &QFutureWatcher<AnalysisResult>::finished, this, [this, watcher]() {
        auto result = watcher->result();
        if (result.success) {
            m_currentFile = std::make_unique<atlus::BinaryFile>(std::move(result.binary));
            m_currentPE = std::make_unique<atlus::PEInfo>(std::move(result.pe));
            m_currentIs64Bit = m_currentPE->is_64bit;

            m_functionsPanel->setFunctions(result.functions);
            m_sectionsPanel->setSections(m_currentPE->sections);
            m_importsPanel->setImports(m_currentPE->imports);
            m_hexPanel->view()->setData(m_currentFile->bytes(), m_currentFile->size());
            m_disasmPanel->clear();
            m_pseudoPanel->clear();
        }
        onAnalysisComplete(result.success, result.message);
        watcher->deleteLater();
    });

    onAnalysisStarted(path);

    QFuture<AnalysisResult> future = QtConcurrent::run(QThreadPool::globalInstance(), [path, opts = m_analysisOptions]() -> AnalysisResult {
        AnalysisResult r;
        r.binary = atlus::Loader::load(path.toStdString());
        if (r.binary.empty()) {
            r.message = "Failed to load binary";
            return r;
        }

        r.pe = atlus::PEParser::parse(r.binary);
        if (!r.pe.valid) {
            r.message = "Not a valid PE file";
            r.success = true;
            return r;
        }

        atlus::Analyzer analyzer(r.pe.is_64bit ? atlus::Disassembler::Mode::X86_64
                                                 : atlus::Disassembler::Mode::X86_32);
        for (const auto& sec : r.pe.sections) {
            if (sec.name == ".text" || (sec.flags & 0x20000000)) { // IMAGE_SCN_MEM_EXECUTE
                auto sec_fns = analyzer.find_functions(sec, r.pe.image_base + sec.vaddr);
                r.functions.insert(r.functions.end(), sec_fns.begin(), sec_fns.end());
            }
        }
        if (opts.analyzeXRefs)
            atlus::Analyzer::build_xrefs(r.functions);
        r.success = true;
        r.message = QString("%1 | %2 sections | %3 functions")
                        .arg(QString::fromStdString(r.binary.path))
                        .arg(r.pe.sections.size())
                        .arg(r.functions.size());
        return r;
    });

    watcher->setFuture(future);
}

void MainWindow::clearAllPanels()
{
    m_functionsPanel->clear();
    m_sectionsPanel->clear();
    m_importsPanel->clear();
    m_hexPanel->view()->clear();
    m_disasmPanel->clear();
    m_pseudoPanel->clear();
    m_xrefsPanel->clear();
    m_aobPanel->clear();
    if (m_cfgPanel) m_cfgPanel->clear();
    if (m_callGraphPanel) m_callGraphPanel->clear();
    m_currentFile.reset();
    m_currentPE.reset();
    if (m_reanalyzeAct)
        m_reanalyzeAct->setEnabled(false);
}

void MainWindow::onFileOpen()
{
    QString path = QFileDialog::getOpenFileName(
        this, "Open PE Binary", QString(),
        "PE files (*.exe *.dll *.sys *.bin);;All files (*)");
    if (path.isEmpty()) return;

    // Show Analysis Options dialog before starting analysis
    QSettings settings("Atlus", "Atlus");
    AnalysisOptionsDialog dlg(m_analysisOptions, this);
    if (dlg.exec() != QDialog::Accepted)
        return; // User cancelled, don't load the file

    applyAnalysisOptions(dlg.options());
    m_analysisOptions.save(settings);

    clearAllPanels();
    runAnalysis(path);
}

void MainWindow::onFileOpenDiff()
{
    QMessageBox::information(this, "Diff Mode", "Diff analysis not yet implemented in Qt6 UI.");
}

void MainWindow::onAnalysisStarted(const QString& path)
{
    m_statusLabel->setText("Loading: " + path);
    m_progressBar->setVisible(true);
    m_analysisStageLabel->setVisible(true);
    m_analysisStageLabel->setText("Initializing...");
    m_openAct->setEnabled(false);
    m_openDiffAct->setEnabled(false);
}

void MainWindow::onAnalysisComplete(bool success, const QString& msg)
{
    m_progressBar->setVisible(false);
    m_analysisStageLabel->setVisible(false);
    m_openAct->setEnabled(true);
    m_openDiffAct->setEnabled(true);

    if (success) {
        m_statusLabel->setText("Ready | " + msg);
        appendLog("Loaded: " + msg);
        if (m_currentFile && !m_currentFile->path.empty())
            updateRecentFiles(QString::fromStdString(m_currentFile->path));
        m_reanalyzeAct->setEnabled(true);

        // Request call graph generation if enabled
        if (m_analysisOptions.enableRevng && m_analysisOptions.revngRenderCallGraph
            && m_currentFile && m_callGraphPanel) {
            m_callGraphPanel->setStatus("Generating call graph...");
            emit requestCallGraphGeneration(QString::fromStdString(m_currentFile->path));
        }

        // Update analysis options for workers
        if (m_revngWorker) m_revngWorker->setAnalysisOptions(m_analysisOptions);
        if (m_analysisWorker) m_analysisWorker->setAnalysisOptions(m_analysisOptions);
    } else {
        m_statusLabel->setText("Error: " + msg);
        appendLog("Error: " + msg);
        QMessageBox::critical(this, "Load Error", msg);
    }
}

void MainWindow::onFunctionSelected(const atlus::Function* fn)
{
    if (!fn || !m_currentFile || !m_currentPE) return;

    appendLog(QString("Selected: %1 @ 0x%2 (size %3)")
              .arg(QString::fromStdString(fn->name))
              .arg(fn->start_address, 0, 16)
              .arg(fn->size_bytes));

    // Disassemble selected function (convert VA -> file offset via sections)
    atlus::Disassembler disasm(m_currentIs64Bit
        ? atlus::Disassembler::Mode::X86_64
        : atlus::Disassembler::Mode::X86_32);

    uint64_t fileOffset = 0;
    const uint8_t* rawData = nullptr;
    size_t rawSize = 0;
    for (const auto& sec : m_currentPE->sections) {
        uint64_t secVaStart = m_currentPE->image_base + sec.vaddr;
        uint64_t secVaEnd   = secVaStart + sec.raw_size;
        if (fn->start_address >= secVaStart && fn->start_address < secVaEnd) {
            fileOffset = sec.raw_offset + (fn->start_address - secVaStart);
            rawData = m_currentFile->bytes() + fileOffset;
            uint64_t offsetInSec = fn->start_address - secVaStart;
            size_t available = (offsetInSec < sec.raw_size) ? (sec.raw_size - static_cast<uint32_t>(offsetInSec)) : 0;
            rawSize = qMin(fn->size_bytes, available);
            break;
        }
    }

    if (rawData && rawSize > 0) {
        auto instructions = disasm.disassemble(rawData, rawSize, fn->start_address, 10000);
        m_disasmPanel->setInstructions(instructions);
    } else {
        m_disasmPanel->clear();
    }

    // Populate xrefs
    m_xrefsPanel->setCallers(fn->calls_in);
    m_xrefsPanel->setCallees(fn->calls_out);

    // Request decompilation via worker thread
    if (m_analysisOptions.enableRevng) {
        m_pseudoPanel->setText("Decompiling...");
        emit requestDecompile(fn->start_address,
                              QString::fromStdString(m_currentFile->path),
                              m_currentIs64Bit);

        // Also request CFG generation if enabled (runs in parallel on separate thread)
        if (m_analysisOptions.revngEmitCFG && m_cfgPanel) {
            m_cfgPanel->setStatus("Generating CFG...");
            emit requestCFGGeneration(fn->start_address,
                                      QString::fromStdString(m_currentFile->path));
        }
    } else {
        m_pseudoPanel->setText("Decompiler not enabled.\n\nEnable rev.ng via:\nAnalysis -> Decompiler -> Enable rev.ng");
    }
}

void MainWindow::onInstructionSelected(const atlus::Instruction* ins)
{
    if (!ins) return;
    appendLog(QString("Ins @ 0x%1: %2 %3")
              .arg(ins->address, 0, 16)
              .arg(QString::fromStdString(ins->mnemonic))
              .arg(QString::fromStdString(ins->operands)));
}

void MainWindow::onXrefSelected(uint64_t address)
{
    appendLog(QString("Jump to xref @ 0x%1").arg(address, 0, 16));
    // Future: scroll hex view and disassembly to this address
}

void MainWindow::onPseudocodeReady(const QString& text)
{
    m_pseudoPanel->setText(text);
}

void MainWindow::onDecompileError(const QString& message)
{
    m_pseudoPanel->setText("Decompilation failed:\n" + message);
    appendLog("Decompile error: " + message);
}

void MainWindow::appendLog(const QString& text)
{
    if (m_logPanel) {
        m_logPanel->append(text);
    }
}

void MainWindow::applyDarkTheme()
{
    Theme::applyToApplication();
}

void MainWindow::applyFontSize(int size)
{
    QFont font("Consolas", size);
    if (m_logPanel) m_logPanel->setFont(font);
    // Panels pick up via QApplication font + QSS; explicit override if needed
    QApplication::setFont(QFont("JetBrains Mono", size));
}

void MainWindow::onSettings()
{
    QSettings settings("Atlus", "Atlus");
    AppSettings current;
    current.load(settings);

    SettingsDialog dlg(current, this);
    if (dlg.exec() != QDialog::Accepted)
        return;

    AppSettings s = dlg.settings();
    s.save(settings);

    applyFontSize(s.fontSize);
    if (m_revngWorker)
        m_revngWorker->setPath(s.revngPath);
    m_analysisOptions.revngPath = s.revngPath;
    m_analysisOptions.save(settings);
}

void MainWindow::onOpenRecent()
{
    auto* act = qobject_cast<QAction*>(sender());
    if (!act) return;
    QString path = act->data().toString();
    if (path.isEmpty()) return;

    // Show Analysis Options dialog before starting analysis
    QSettings settings("Atlus", "Atlus");
    AnalysisOptionsDialog dlg(m_analysisOptions, this);
    if (dlg.exec() != QDialog::Accepted)
        return; // User cancelled, don't load the file

    applyAnalysisOptions(dlg.options());
    m_analysisOptions.save(settings);

    clearAllPanels();
    runAnalysis(path);
}

void MainWindow::onToggleDock()
{
    auto* act = qobject_cast<QAction*>(sender());
    if (!act) return;
    auto* dock = qobject_cast<QDockWidget*>(act->data().value<QDockWidget*>());
    if (!dock) return;

    if (dock->isVisible())
        dock->hide();
    else
        dock->show();
}

void MainWindow::updateRecentFiles(const QString& path)
{
    QSettings settings("Atlus", "Atlus");
    QStringList recent = settings.value("recentFiles").toStringList();
    recent.removeAll(path);
    recent.prepend(path);
    while (recent.size() > 10)
        recent.removeLast();
    settings.setValue("recentFiles", recent);
    populateRecentMenu();
}

void MainWindow::populateRecentMenu()
{
    m_recentMenu->clear();
    m_recentActions.clear();

    QSettings settings("Atlus", "Atlus");
    QStringList recent = settings.value("recentFiles").toStringList();

    if (recent.isEmpty()) {
        auto* empty = m_recentMenu->addAction("(No recent files)");
        empty->setEnabled(false);
        return;
    }

    for (const QString& path : recent) {
        auto* act = m_recentMenu->addAction(path);
        act->setData(path);
        connect(act, &QAction::triggered, this, &MainWindow::onOpenRecent);
        m_recentActions.append(act);
    }

    m_recentMenu->addSeparator();
    auto* clear = m_recentMenu->addAction("Clear Recent Files");
    connect(clear, &QAction::triggered, this, [this]() {
        QSettings("Atlus", "Atlus").remove("recentFiles");
        populateRecentMenu();
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Analysis menu
// ─────────────────────────────────────────────────────────────────────────────

void MainWindow::setupAnalysisMenu()
{
    m_analysisMenu = menuBar()->addMenu("&Analysis");

    m_analysisOptionsAct = m_analysisMenu->addAction("Analysis &Options...");
    m_analysisOptionsAct->setShortcut(QKeySequence("Ctrl+Shift+A"));
    connect(m_analysisOptionsAct, &QAction::triggered, this, &MainWindow::onAnalysisOptions);

    m_analysisMenu->addSeparator();

    m_reanalyzeAct = m_analysisMenu->addAction("&Re-analyze");
    m_reanalyzeAct->setShortcut(QKeySequence("Ctrl+R"));
    m_reanalyzeAct->setEnabled(false);
    connect(m_reanalyzeAct, &QAction::triggered, this, &MainWindow::onReanalyze);

    m_analysisMenu->addSeparator();

    m_decompilerSubMenu = m_analysisMenu->addMenu("&Decompiler");

    m_enableRevngAct = m_decompilerSubMenu->addAction("Enable &rev.ng");
    m_enableRevngAct->setCheckable(true);
    m_enableRevngAct->setChecked(false);
    connect(m_enableRevngAct, &QAction::toggled, this, &MainWindow::onToggleRevng);

    m_decompilerSubMenu->addSeparator();

    auto* configRevngAct = m_decompilerSubMenu->addAction("&Configure rev.ng...");
    connect(configRevngAct, &QAction::triggered, this, &MainWindow::onAnalysisOptions);
}

void MainWindow::onAnalysisOptions()
{
    QSettings settings("Atlus", "Atlus");
    AnalysisOptionsDialog dlg(m_analysisOptions, this);
    if (dlg.exec() != QDialog::Accepted)
        return;

    applyAnalysisOptions(dlg.options());
    m_analysisOptions.save(settings);

    // If a binary is loaded, re-run analysis with new options immediately
    if (m_currentFile && !m_currentFile->path.empty()) {
        QString path = QString::fromStdString(m_currentFile->path);
        clearAllPanels();
        runAnalysis(path);
        appendLog("Re-analyzing with new options...");
    }
}

void MainWindow::onReanalyze()
{
    if (!m_currentFile || m_currentFile->path.empty()) return;
    QString path = QString::fromStdString(m_currentFile->path);
    clearAllPanels();
    runAnalysis(path);
}

void MainWindow::onToggleRevng(bool enabled)
{
    m_analysisOptions.enableRevng = enabled;
    QSettings settings("Atlus", "Atlus");
    m_analysisOptions.save(settings);

    if (!enabled)
        m_pseudoPanel->setText("Decompiler not enabled.\n\nEnable rev.ng via:\nAnalysis -> Decompiler -> Enable rev.ng");
    else
        m_pseudoPanel->setText("rev.ng enabled. Select a function to decompile.");
}

void MainWindow::onDecompilerState(const QString& state)
{
    m_statusLabel->setText(state);
}

void MainWindow::applyAnalysisOptions(const AnalysisOptions& opts)
{
    const bool pathChanged = (opts.revngPath != m_analysisOptions.revngPath);
    m_analysisOptions = opts;
    m_enableRevngAct->setChecked(opts.enableRevng);
    if (pathChanged && m_revngWorker)
        m_revngWorker->setPath(opts.revngPath);
    if (pathChanged && m_analysisWorker)
        m_analysisWorker->setPath(opts.revngPath);

    // Update analysis options for both workers
    if (m_revngWorker)
        m_revngWorker->setAnalysisOptions(opts);
    if (m_analysisWorker)
        m_analysisWorker->setAnalysisOptions(opts);
}

// ─────────────────────────────────────────────────────────────────────────────
// rev.ng Advanced Features
// ─────────────────────────────────────────────────────────────────────────────

void MainWindow::onAnalysisStageChanged(const QString& stage, const QString& message)
{
    // Update the analysis stage label in the status bar
    if (m_analysisStageLabel) {
        m_analysisStageLabel->setVisible(true);
        m_analysisStageLabel->setText(QString("[%1] %2").arg(stage, message));
    }

    // Also update status label with stage information
    if (m_statusLabel && !stage.isEmpty()) {
        m_statusLabel->setText(QString("rev.ng: %1 - %2").arg(stage, message));
    }
}

void MainWindow::onCFGReady(const QString& yaml, uint64_t address)
{
    if (m_cfgPanel) {
        m_cfgPanel->setCFG(yaml, address);
        // Switch to CFG tab if the panel received data
        int cfgTabIndex = m_centralTabs->indexOf(m_cfgPanel);
        if (cfgTabIndex >= 0 && m_analysisOptions.revngEmitCFG) {
            // Optional: auto-switch to CFG tab
            // m_centralTabs->setCurrentIndex(cfgTabIndex);
        }
    }
    appendLog(QString("CFG generated for function @ 0x%1").arg(address, 0, 16));
}

void MainWindow::onCFGError(const QString& message)
{
    if (m_cfgPanel) {
        m_cfgPanel->setStatus("Error: " + message);
    }
    appendLog("CFG Error: " + message);
}

void MainWindow::onCallGraphReady(const QString& svg)
{
    if (m_callGraphPanel) {
        m_callGraphPanel->setSVG(svg);
    }
    appendLog("Call graph generated successfully");
}

void MainWindow::onCallGraphError(const QString& message)
{
    if (m_callGraphPanel) {
        m_callGraphPanel->setStatus("Error: " + message);
    }
    appendLog("Call Graph Error: " + message);
}

void MainWindow::requestCFG(uint64_t address)
{
    if (m_analysisOptions.enableRevng && m_analysisOptions.revngEmitCFG
        && m_currentFile) {
        emit requestCFGGeneration(address, QString::fromStdString(m_currentFile->path));
    }
}

void MainWindow::requestCallGraph()
{
    if (m_analysisOptions.enableRevng && m_analysisOptions.revngRenderCallGraph
        && m_currentFile) {
        emit requestCallGraphGeneration(QString::fromStdString(m_currentFile->path));
    }
}
