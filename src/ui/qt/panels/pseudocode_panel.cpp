#include "pseudocode_panel.h"
#include "theme.h"
#include <QVBoxLayout>
#include <QPlainTextEdit>
#include <QSyntaxHighlighter>
#include <QTextDocument>
#include <QRegularExpression>

class CHighlighter : public QSyntaxHighlighter {
public:
    explicit CHighlighter(QTextDocument* parent = nullptr)
        : QSyntaxHighlighter(parent)
    {
        QTextCharFormat keywordFormat;
        keywordFormat.setForeground(Theme::color(Theme::Keyword));
        keywordFormat.setFontWeight(QFont::Bold);

        QStringList keywords;
        keywords << "auto" << "break" << "case" << "char" << "const" << "continue"
                 << "default" << "do" << "double" << "else" << "enum" << "extern"
                 << "float" << "for" << "goto" << "if" << "int" << "long"
                 << "register" << "return" << "short" << "signed" << "sizeof"
                 << "static" << "struct" << "switch" << "typedef" << "union"
                 << "unsigned" << "void" << "volatile" << "while";

        for (const QString& kw : keywords) {
            HighlightRule rule;
            rule.pattern = QRegularExpression(QString("\\b%1\\b").arg(kw));
            rule.format = keywordFormat;
            rules.append(rule);
        }

        QTextCharFormat typeFormat;
        typeFormat.setForeground(Theme::color(Theme::Type));
        HighlightRule typeRule;
        typeRule.pattern = QRegularExpression("\\b(uint8_t|uint16_t|uint32_t|uint64_t|int8_t|int16_t|int32_t|int64_t|size_t|bool|NULL|true|false)\\b");
        typeRule.format = typeFormat;
        rules.append(typeRule);

        QTextCharFormat commentFormat;
        commentFormat.setForeground(Theme::color(Theme::Comment));
        HighlightRule commentRule;
        commentRule.pattern = QRegularExpression("//.*$");
        commentRule.format = commentFormat;
        rules.append(commentRule);

        QTextCharFormat stringFormat;
        stringFormat.setForeground(Theme::color(Theme::String));
        HighlightRule stringRule;
        stringRule.pattern = QRegularExpression("\".*\"|'.*'");
        stringRule.format = stringFormat;
        rules.append(stringRule);

        QTextCharFormat numberFormat;
        numberFormat.setForeground(Theme::color(Theme::Number));
        HighlightRule numberRule;
        numberRule.pattern = QRegularExpression("\\b[0-9]+\\b|0x[0-9a-fA-F]+");
        numberRule.format = numberFormat;
        rules.append(numberRule);
    }

protected:
    void highlightBlock(const QString& text) override {
        for (const auto& rule : rules) {
            QRegularExpressionMatchIterator it = rule.pattern.globalMatch(text);
            while (it.hasNext()) {
                QRegularExpressionMatch m = it.next();
                setFormat(m.capturedStart(), m.capturedLength(), rule.format);
            }
        }
    }

private:
    struct HighlightRule {
        QRegularExpression pattern;
        QTextCharFormat format;
    };
    QVector<HighlightRule> rules;
};

PseudocodePanel::PseudocodePanel(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setSpacing(2);
    layout->setContentsMargins(2, 2, 2, 2);

    m_editor = new QPlainTextEdit(this);
    m_editor->setReadOnly(true);
    m_editor->setFont(QFont("Consolas", 10));
    new CHighlighter(m_editor->document());
    layout->addWidget(m_editor);
}

void PseudocodePanel::setText(const QString& text)
{
    m_editor->setPlainText(text);
}

void PseudocodePanel::clear()
{
    m_editor->clear();
}
