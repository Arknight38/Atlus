#pragma once

#include <QObject>
#include <QThread>
#include <QString>
#include <cstdint>
#include <memory>
#include "core/revng_decompiler.h"
#include "dialogs/analysis_options_dialog.h"

class RevngWorker : public QObject {
    Q_OBJECT

public:
    explicit RevngWorker(QObject* parent = nullptr);

    void setPath(const QString& path);
    QString path() const;

    void setAnalysisOptions(const AnalysisOptions& opts) { m_opts = opts; }

public slots:
    void init();
    void decompile(uint64_t address, const QString& binaryPath, bool is64Bit);
    void generateCFG(uint64_t address, const QString& binaryPath);
    void generateCallGraph(const QString& binaryPath);

signals:
    void decompileReady(const QString& text);
    void decompileError(const QString& message);
    void stateChanged(const QString& state);
    void progressOutput(const QString& line);

    // Detailed progress reporting
    void analysisStageChanged(const QString& stage, const QString& message);

    // CFG and call graph results
    void cfgReady(const QString& yaml, uint64_t address);
    void cfgError(const QString& message);
    void callGraphReady(const QString& svg);
    void callGraphError(const QString& message);

private:
    void setupProgressCallback();
    void ensureDecompiler(const QString& binaryPath);

    QString m_path;
    QString m_currentBinary;
    std::unique_ptr<atlus::RevngDecompiler> m_decompiler;
    AnalysisOptions m_opts;
};
