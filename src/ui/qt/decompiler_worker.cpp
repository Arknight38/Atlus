#include "decompiler_worker.h"
#include <future>
#include <utility>

RevngWorker::RevngWorker(QObject* parent)
    : QObject(parent)
{
}

void RevngWorker::setPath(const QString& path)
{
    m_path = path;
    // Force re-lift with the updated rev.ng path on the next request
    m_currentBinary.clear();
    m_decompiler.reset();
}

QString RevngWorker::path() const
{
    return m_path;
}

void RevngWorker::setupProgressCallback()
{
    if (!m_decompiler) return;

    m_decompiler->set_progress_callback([this](atlus::AnalysisStage stage, const std::string& message) {
        QString stageName;
        switch (stage) {
            case atlus::AnalysisStage::ImportBinary: stageName = "Import Binary"; break;
            case atlus::AnalysisStage::DetectABI: stageName = "Detect ABI"; break;
            case atlus::AnalysisStage::EmitCFG: stageName = "Generate CFG"; break;
            case atlus::AnalysisStage::RenderCallGraph: stageName = "Render Call Graph"; break;
            case atlus::AnalysisStage::Decompile: stageName = "Decompile"; break;
            case atlus::AnalysisStage::Done: stageName = "Done"; break;
            default: stageName = "Processing"; break;
        }
        emit analysisStageChanged(stageName, QString::fromStdString(message));
        emit stateChanged(stageName + ": " + QString::fromStdString(message));
    });
}

void RevngWorker::ensureDecompiler(const QString& binaryPath)
{
    const bool needsLift = (binaryPath != m_currentBinary)
                        || !m_decompiler
                        || m_decompiler->state() == atlus::DecompilerState::Error;

    if (needsLift) {
        m_currentBinary = binaryPath;
        m_decompiler.reset();

        try {
            m_decompiler = atlus::RevngDecompiler::create();
        } catch (const std::exception& e) {
            emit decompileError(QString::fromStdString(e.what()));
            emit stateChanged("Error");
            return;
        }

        if (!m_path.isEmpty())
            m_decompiler->set_path(m_path.toStdString());

        setupProgressCallback();

        m_decompiler->set_output_callback([this](const std::string& line) {
            emit progressOutput(QString::fromStdString("[revng] " + line));
        });
    }
}

void RevngWorker::init()
{
    emit stateChanged("Decompiler idle");
}

void RevngWorker::decompile(uint64_t address, const QString& binaryPath, bool is64Bit)
{
    Q_UNUSED(is64Bit)

    // Re-lift only when the binary changes or the previous lift failed
    const bool needsLift = (binaryPath != m_currentBinary)
                        || !m_decompiler
                        || m_decompiler->state() == atlus::DecompilerState::Error;

    if (needsLift) {
        m_currentBinary = binaryPath;
        m_decompiler.reset();
        emit stateChanged("Lifting...");

        try {
            m_decompiler = atlus::RevngDecompiler::create();
        } catch (const std::exception& e) {
            emit decompileError(QString::fromStdString(e.what()));
            emit stateChanged("Error");
            return;
        }

        if (!m_path.isEmpty())
            m_decompiler->set_path(m_path.toStdString());

        setupProgressCallback();

        m_decompiler->set_output_callback([this](const std::string& line) {
            emit progressOutput(QString::fromStdString("[revng] " + line));
        });

        std::promise<std::pair<bool, std::string>> liftPromise;
        auto liftFuture = liftPromise.get_future();

        m_decompiler->lift_async(binaryPath.toStdString(),
            [&liftPromise](bool ok, std::string err) {
                liftPromise.set_value({ok, std::move(err)});
            });

        auto [liftOk, liftErr] = liftFuture.get();
        if (!liftOk) {
            emit decompileError(QString::fromStdString(liftErr));
            emit stateChanged("Error");
            return;
        }
    }

    emit stateChanged("Decompiling...");
    auto result = m_decompiler->decompile(address);

    if (!result.error.empty()) {
        emit decompileError(QString::fromStdString(result.error));
        emit stateChanged("Error");
    } else {
        emit decompileReady(QString::fromStdString(result.c_code));
        emit stateChanged("Ready");
    }
}

void RevngWorker::generateCFG(uint64_t address, const QString& binaryPath)
{
    if (!m_opts.revngEmitCFG) {
        emit cfgError("CFG generation is disabled in analysis options");
        return;
    }

    ensureDecompiler(binaryPath);

    if (!m_decompiler || m_decompiler->state() != atlus::DecompilerState::Ready) {
        emit cfgError("Decompiler not ready");
        return;
    }

    std::promise<atlus::CFGResult> resultPromise;
    auto resultFuture = resultPromise.get_future();

    m_decompiler->emit_cfg_async(address, [&resultPromise](atlus::CFGResult result) {
        resultPromise.set_value(std::move(result));
    });

    auto result = resultFuture.get();
    if (!result.success) {
        emit cfgError(QString::fromStdString(result.error));
    } else {
        emit cfgReady(QString::fromStdString(result.yaml), address);
    }
}

void RevngWorker::generateCallGraph(const QString& binaryPath)
{
    if (!m_opts.revngRenderCallGraph) {
        emit callGraphError("Call graph generation is disabled in analysis options");
        return;
    }

    ensureDecompiler(binaryPath);

    if (!m_decompiler || m_decompiler->state() != atlus::DecompilerState::Ready) {
        emit callGraphError("Decompiler not ready");
        return;
    }

    std::promise<atlus::CallGraphResult> resultPromise;
    auto resultFuture = resultPromise.get_future();

    m_decompiler->render_call_graph_async([&resultPromise](atlus::CallGraphResult result) {
        resultPromise.set_value(std::move(result));
    });

    auto result = resultFuture.get();
    if (!result.success) {
        emit callGraphError(QString::fromStdString(result.error));
    } else {
        emit callGraphReady(QString::fromStdString(result.svg));
    }
}
