#pragma once

#include <QMainWindow>
#include <QDockWidget>
#include <memory>
#include "dialogs/analysis_options_dialog.h"

QT_BEGIN_NAMESPACE
class QAction;
class QMenu;
class QLabel;
class QProgressBar;
class QTextEdit;
class QTabWidget;
QT_END_NAMESPACE

namespace atlus {
struct BinaryFile;
struct PEInfo;
struct Function;
struct Instruction;
}

class FunctionsPanel;
class SectionsPanel;
class ImportsPanel;
class HexPanel;
class DisassemblyPanel;
class PseudocodePanel;
class XrefsPanel;
class AobPanel;
class CFGPanel;
class CallGraphPanel;
class RevngWorker;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

    void appendLog(const QString& text);

public slots:
    void onFileOpen();
    void onFileOpenDiff();
    void onOpenRecent();
    void onSettings();
    void onToggleDock();
    void onAnalysisStarted(const QString& path);
    void onAnalysisComplete(bool success, const QString& msg);
    void onFunctionSelected(const atlus::Function* fn);
    void onInstructionSelected(const atlus::Instruction* ins);
    void onXrefSelected(uint64_t address);
    void onPseudocodeReady(const QString& text);
    void onDecompileError(const QString& message);
    void onAnalysisOptions();
    void onReanalyze();
    void onToggleRevng(bool enabled);
    void onDecompilerState(const QString& state);

    // rev.ng advanced features
    void onAnalysisStageChanged(const QString& stage, const QString& message);
    void onCFGReady(const QString& yaml, uint64_t address);
    void onCFGError(const QString& message);
    void onCallGraphReady(const QString& svg);
    void onCallGraphError(const QString& message);
    void requestCFG(uint64_t address);
    void requestCallGraph();

signals:
    void requestAnalysis(const QString& path);
    void requestDiffAnalysis(const QString& pathA, const QString& pathB);
    void requestDecompile(uint64_t address, const QString& binaryPath, bool is64Bit);
    void requestResetDecompiler();
    void requestCFGGeneration(uint64_t address, const QString& binaryPath);
    void requestCallGraphGeneration(const QString& binaryPath);

private:
    void setupMenuBar();
    void setupAnalysisMenu();
    void setupStatusBar();
    void setupDockAreas();
    void setupPanels();
    void applyDarkTheme();
    void applyFontSize(int size);
    void runAnalysis(const QString& path);
    void clearAllPanels();
    void updateRecentFiles(const QString& path);
    void populateRecentMenu();
    void applyAnalysisOptions(const AnalysisOptions& opts);

    QMenu* m_fileMenu = nullptr;
    QMenu* m_recentMenu = nullptr;
    QMenu* m_viewMenu = nullptr;
    QMenu* m_analysisMenu = nullptr;
    QMenu* m_decompilerSubMenu = nullptr;
    QMenu* m_helpMenu = nullptr;
    QAction* m_openAct = nullptr;
    QAction* m_openDiffAct = nullptr;
    QAction* m_settingsAct = nullptr;
    QAction* m_exitAct = nullptr;
    QAction* m_analysisOptionsAct = nullptr;
    QAction* m_reanalyzeAct = nullptr;
    QAction* m_enableRevngAct = nullptr;
    QList<QAction*> m_recentActions;

    QLabel* m_statusLabel = nullptr;
    QProgressBar* m_progressBar = nullptr;

    // Panels
    FunctionsPanel*     m_functionsPanel = nullptr;
    SectionsPanel*      m_sectionsPanel = nullptr;
    ImportsPanel*       m_importsPanel = nullptr;
    HexPanel*           m_hexPanel = nullptr;
    DisassemblyPanel*   m_disasmPanel = nullptr;
    PseudocodePanel*    m_pseudoPanel = nullptr;
    XrefsPanel*         m_xrefsPanel = nullptr;
    AobPanel*           m_aobPanel = nullptr;
    CFGPanel*           m_cfgPanel = nullptr;
    CallGraphPanel*     m_callGraphPanel = nullptr;
    QTextEdit*          m_logPanel = nullptr;
    QTabWidget*         m_centralTabs = nullptr;
    QTabWidget*         m_bottomTabs = nullptr;

    // Decompiler worker on dedicated thread
    QThread*            m_revngThread = nullptr;
    RevngWorker*        m_revngWorker = nullptr;

    // Additional workers for parallel processing
    QThread*            m_analysisThread = nullptr;
    RevngWorker*        m_analysisWorker = nullptr;

    // Analysis state tracking
    QLabel*             m_analysisStageLabel = nullptr;

    // Analysis configuration
    AnalysisOptions m_analysisOptions;

    // Current session data
    std::unique_ptr<atlus::BinaryFile> m_currentFile;
    std::unique_ptr<atlus::PEInfo> m_currentPE;
    bool m_currentIs64Bit = false;
};
