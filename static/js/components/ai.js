/**
 * AI analysis page component.
 * Renders LLM output as a two-column Markdown report with a manual review flow.
 */

let currentAIReport = null;

window.addEventListener('componentLoaded', (e) => {
    if (e.detail.name === 'ai') {
        initAIPage();
    }
});

function initAIPage() {
    const page = document.getElementById('page-ai');
    if (!page || page.dataset.aiInitialized === 'true') return;
    page.dataset.aiInitialized = 'true';

    document.getElementById('btnAIAnalyze')?.addEventListener('click', runAIAnalysis);
    document.getElementById('btnAIReanalyze')?.addEventListener('click', runAIAnalysis);
    document.getElementById('btnAIExportPdf')?.addEventListener('click', exportAIReportPdf);
    document.getElementById('btnAIReviewEdit')?.addEventListener('click', openAIReviewModal);
    document.getElementById('btnAIReviewClose')?.addEventListener('click', closeAIReviewModal);
    document.getElementById('btnAIReviewCancel')?.addEventListener('click', closeAIReviewModal);
    document.getElementById('btnAIReviewSave')?.addEventListener('click', saveAIReviewEdits);
}

async function loadAIData(status, pageDataCache) {
    const completed = status.steps_completed || {};
    const canGenerateReport = Boolean(completed.threat && completed.relations && completed.chains);

    if (!completed.rules) return;

    document.getElementById('aiInputEmpty').style.display = 'none';
    document.getElementById('aiInputFilled').style.display = 'block';
    document.getElementById('aiActionSection').style.display = canGenerateReport ? 'block' : 'none';

    if (!canGenerateReport) {
        setVisible('aiResultsSection', false);
        setVisible('aiProgressSection', false);
        setVisible('aiActionArea', true);
        setDisabled('btnAIAnalyze', true);
        return;
    }

    setDisabled('btnAIAnalyze', false);

    try {
        const llmStatus = await apiGet('/llm/status');
        updateLLMMode(llmStatus);
    } catch (error) {
        updateLLMMode({ mode: 'unknown', available: false });
    }

    try {
        const rulesData = await DataCache.get('rules');
        const data = rulesData?.data || {};
        const alertsByRule = data.alerts_by_rule || {};
        const bySeverity = data.by_severity || {};

        setText('aiInAlerts', Object.keys(alertsByRule).length || data.total_alerts || 0);
        setText('aiInHighAlerts', bySeverity.high || 0);

        const savedReview = loadSavedReview();
        if (savedReview) {
            displayAIResult(savedReview);
            return;
        }

        const aiData = normalizeAIResponse(pageDataCache || await tryGetAIResult() || await DataCache.get('ai'));
        if (aiData && !aiData.error) displayAIResult(aiData);
    } catch (error) {
        console.error('Load AI page data error:', error);
    }
}

async function tryGetAIResult() {
    try {
        return await apiGet('/llm/result');
    } catch (_) {
        return null;
    }
}

async function runAIAnalysis() {
    try {
        const status = await getSystemStatus();
        const completed = normalizeStepsCompleted(status);
        if (!(completed.threat && completed.relations && completed.chains)) {
            alert('请先完成威胁检测、关系挖掘和攻击链重建，再生成 AI 分析报告。');
            return;
        }

        setVisible('aiProgressSection', true);
        setVisible('aiResultsSection', false);
        setVisible('aiActionArea', false);
        setDisabled('btnAIAnalyze', true);

        updateAIProgress(5, '检查 LLM 服务状态...');
        const statusResponse = await apiGet('/llm/status');
        updateLLMMode(statusResponse);

        updateAIProgress(15, '整理告警、关系图与攻击链上下文...');
        const response = await apiPost('/llm/analyze');
        const report = normalizeAIResponse(response);

        updateAIProgress(100, '分析完成');
        window.localStorage.removeItem('trace_eye_ai_review_report');

        setTimeout(() => {
            setVisible('aiProgressSection', false);
            setDisabled('btnAIAnalyze', false);
            displayAIResult(report);
        }, 350);
    } catch (error) {
        setVisible('aiProgressSection', false);
        setVisible('aiActionArea', true);
        setDisabled('btnAIAnalyze', false);
        alert(`AI 分析失败: ${error.message}`);
    }
}

function normalizeAIResponse(response) {
    if (!response) return null;
    const result = response.result || response;
    if (result.error) return result;

    const story = result.attack_story || {};
    const report = result.analysis_report || {};
    const stats = result.statistics || {
        original_alerts: result.original_alerts_count || 0,
        filtered_alerts: result.filtered_alerts_count || report.total_filtered || 0
    };

    const iocs = story.ioc_list || story.iocs || [];
    const recommendations = result.recommendations || story.recommendations || [];
    const diagnosisMarkdown = result.diagnosis_markdown || buildDiagnosisMarkdown(result, story, report);
    const remediationMarkdown = result.remediation_markdown || buildRemediationMarkdown(story, recommendations);

    return {
        ...result,
        attack_story: { ...story, ioc_list: iocs, recommendations },
        statistics: stats,
        diagnosis_markdown: diagnosisMarkdown,
        remediation_markdown: remediationMarkdown,
        manual_review: result.manual_review || inferManualReview(story, stats),
        analyzed_at: result.analyzed_at || result.analysis_time || new Date().toISOString()
    };
}

function normalizeStepsCompleted(status) {
    const completed = {};
    if (status?.steps_status) {
        for (const [stepId, stepInfo] of Object.entries(status.steps_status)) {
            completed[stepId] = Boolean(stepInfo.completed);
        }
    }
    return { ...completed, ...(status?.steps_completed || {}) };
}

function displayAIResult(result) {
    if (!result || result.error) {
        setVisible('aiResultsSection', false);
        setVisible('aiActionArea', true);
        return;
    }

    currentAIReport = normalizeAIResponse(result);
    const story = currentAIReport.attack_story || {};
    const stats = currentAIReport.statistics || {};
    const iocs = story.ioc_list || [];

    setVisible('aiResultsSection', true);
    setVisible('aiActionArea', false);

    const threatLevel = story.threat_level || 'unknown';
    const threatIcons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', unknown: '⚠' };

    setText('aiTimestamp', new Date(currentAIReport.analyzed_at).toLocaleString('zh-CN'));
    setText('aiThreatIcon', threatIcons[threatLevel] || '⚠');
    setText('aiThreatText', story.summary || story.threat_summary || 'LLM 已完成系统诊断');
    renderInlineMarkdown(
        'aiSummary',
        story.attack_narrative
            ? `**摘要：** ${compactText(story.attack_narrative, 220)}`
            : '**摘要：** 报告已生成，请查看左右两侧 Markdown 内容。'
    );
    setText('aiOriginalCount', stats.original_alerts || currentAIReport.original_alerts_count || 0);
    setText('aiFilteredCount', stats.filtered_alerts || currentAIReport.filtered_alerts_count || 0);
    setText('aiStagesCount', story.attack_stages?.length || 0);
    setText('aiIocCount', iocs.length || 0);

    renderMarkdown('aiDiagnosisMarkdown', currentAIReport.diagnosis_markdown);
    renderMarkdown('aiRemediationMarkdown', currentAIReport.remediation_markdown);
    renderManualReview(currentAIReport.manual_review);
}

function buildDiagnosisMarkdown(result, story, report) {
    const stats = result.statistics || {};
    const severity = report.severity_summary || {};
    const stages = story.attack_stages || [];
    const findings = story.key_findings || [];
    const iocs = story.ioc_list || story.iocs || [];

    const lines = [
        '# 系统诊断报告',
        '',
        `## 威胁等级`,
        `- 当前等级: **${story.threat_level || 'unknown'}**`,
        `- 摘要: ${story.summary || story.threat_summary || '暂无摘要'}`,
        '',
        '## 告警概览',
        `- 原始告警: **${result.original_alerts_count || stats.original_alerts || 0}**`,
        `- 降噪后告警: **${result.filtered_alerts_count || stats.filtered_alerts || report.total_filtered || 0}**`,
        `- 高危告警: **${severity.high || 0}**`,
        `- 中危告警: **${severity.medium || 0}**`,
        '',
        '## 主要问题',
        ...(findings.length ? findings.map(item => `- ${item}`) : ['- 未发现可结构化提取的关键问题，建议人工查看原始告警。']),
        '',
        '## 攻击阶段证据',
        ...(stages.length ? stages.map((stage, index) => {
            const evidence = (stage.evidence || []).map(item => `  - 证据: ${item}`).join('\n');
            return `${index + 1}. **${stage.stage || '未命名阶段'}**: ${stage.description || '暂无描述'}${evidence ? `\n${evidence}` : ''}`;
        }) : ['- 暂无明确攻击阶段。']),
        '',
        '## IOC 指标',
        ...(iocs.length ? iocs.map(ioc => `- \`${ioc.type || 'unknown'}\`: ${ioc.value || '-'} ${ioc.description ? `- ${ioc.description}` : ''}`) : ['- 暂无可提取 IOC。'])
    ];

    return lines.join('\n');
}

function buildRemediationMarkdown(story, recommendations) {
    const stages = story.attack_stages || [];
    const iocs = story.ioc_list || story.iocs || [];

    const lines = [
        '# 系统修复建议',
        '',
        '## 立即处置',
        ...(recommendations.length ? recommendations.map(item => `- ${item}`) : [
            '- 隔离受影响主机，避免横向移动继续扩散。',
            '- 冻结可疑账户并轮换相关凭据。',
            '- 备份关键日志、进程列表、网络连接和可疑文件样本。'
        ]),
        '',
        '## 分阶段修复',
        ...(stages.length ? stages.map(stage => `- **${stage.stage || '异常阶段'}**: ${stage.description || '复核该阶段关联资产，并补充检测规则。'}`) : [
            '- 对告警涉及的主机、进程、文件和网络连接进行人工复核。',
            '- 将误报和真实威胁分别沉淀为白名单与新检测规则。'
        ]),
        '',
        '## IOC 封禁与监控',
        ...(iocs.length ? iocs.map(ioc => `- 将 \`${ioc.value || '-'}\` 加入 ${ioc.type || 'IOC'} 监控/阻断列表。`) : [
            '- 暂无 IOC 时，应基于高危告警主体补充主机级 EDR 排查。'
        ]),
        '',
        '## 后续加固',
        '- 建立复盘记录，补充检测规则和响应剧本。',
        '- 对关键资产开启更高等级日志留存与异常行为监控。',
        '- 在变更完成后执行二次扫描，确认告警数量下降。'
    ];

    return lines.join('\n');
}

function inferManualReview(story, stats) {
    const level = story.threat_level || 'unknown';
    const original = stats.original_alerts || 0;
    const required = ['critical', 'high', 'unknown'].includes(level) || original > 20;
    return {
        required,
        title: required ? '建议人工复核' : '可抽样复核',
        reason: required
            ? 'LLM 识别到较高风险或较多告警，建议安全分析师确认证据链和修复优先级。'
            : '当前风险较低，可由分析师抽样确认后归档。'
    };
}

function renderManualReview(review) {
    const normalized = review || { required: true, title: '建议人工复核', reason: '缺少复核判断，建议人工确认。' };
    const pill = document.getElementById('aiReviewRequired');
    if (pill) {
        pill.textContent = normalized.required ? '需要复核' : '可选复核';
        pill.classList.toggle('required', !!normalized.required);
        pill.classList.toggle('optional', !normalized.required);
    }
    setText('aiReviewTitle', normalized.title || (normalized.required ? '建议人工复核' : '可选复核'));
    setText('aiReviewReason', normalized.reason || '');
}

function openAIReviewModal() {
    if (!currentAIReport) return;
    document.getElementById('aiReviewDiagnosisInput').value = currentAIReport.diagnosis_markdown || '';
    document.getElementById('aiReviewRemediationInput').value = currentAIReport.remediation_markdown || '';
    document.getElementById('aiReviewNoteInput').value = currentAIReport.review_note || '';
    document.getElementById('aiReviewModal').classList.add('active');
}

function closeAIReviewModal() {
    document.getElementById('aiReviewModal')?.classList.remove('active');
}

function saveAIReviewEdits() {
    if (!currentAIReport) return;
    currentAIReport = {
        ...currentAIReport,
        diagnosis_markdown: document.getElementById('aiReviewDiagnosisInput').value,
        remediation_markdown: document.getElementById('aiReviewRemediationInput').value,
        review_note: document.getElementById('aiReviewNoteInput').value,
        manual_review: {
            required: false,
            title: '已人工复核',
            reason: document.getElementById('aiReviewNoteInput').value || '人工已确认并保存修改。'
        }
    };
    window.localStorage.setItem('trace_eye_ai_review_report', JSON.stringify(currentAIReport));
    displayAIResult(currentAIReport);
    closeAIReviewModal();
}

function loadSavedReview() {
    try {
        const raw = window.localStorage.getItem('trace_eye_ai_review_report');
        return raw ? JSON.parse(raw) : null;
    } catch (_) {
        return null;
    }
}

function exportAIReportPdf() {
    if (!currentAIReport) return;
    document.body.classList.add('print-ai-report');
    const oldTitle = document.title;
    document.title = `Trace-Eye AI Report ${new Date().toISOString().slice(0, 10)}`;
    window.print();
    setTimeout(() => {
        document.body.classList.remove('print-ai-report');
        document.title = oldTitle;
    }, 500);
}

function renderMarkdown(elementId, markdown) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.innerHTML = markdownToHtml(markdown || '暂无内容');
}

function renderInlineMarkdown(elementId, markdown) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.innerHTML = inlineMarkdown(markdown || '');
}

function markdownToHtml(markdown) {
    const lines = String(markdown).replace(/\r\n/g, '\n').split('\n');
    const html = [];
    let listOpen = false;
    let orderedOpen = false;
    let paragraph = [];
    let inCode = false;
    let codeLines = [];

    const flushParagraph = () => {
        if (!paragraph.length) return;
        html.push(`<p>${inlineMarkdown(paragraph.join(' '))}</p>`);
        paragraph = [];
    };
    const closeLists = () => {
        if (listOpen) html.push('</ul>');
        if (orderedOpen) html.push('</ol>');
        listOpen = false;
        orderedOpen = false;
    };

    for (const line of lines) {
        if (line.trim().startsWith('```')) {
            if (inCode) {
                html.push(`<pre><code>${escapeHtml(codeLines.join('\n'))}</code></pre>`);
                codeLines = [];
                inCode = false;
            } else {
                flushParagraph();
                closeLists();
                inCode = true;
            }
            continue;
        }
        if (inCode) {
            codeLines.push(line);
            continue;
        }

        const trimmed = line.trim();
        if (!trimmed) {
            flushParagraph();
            closeLists();
            continue;
        }

        const heading = trimmed.match(/^(#{1,4})\s+(.+)$/);
        if (heading) {
            flushParagraph();
            closeLists();
            const level = Math.min(heading[1].length + 1, 5);
            html.push(`<h${level}>${inlineMarkdown(heading[2])}</h${level}>`);
            continue;
        }

        const bullet = trimmed.match(/^[-*]\s+(.+)$/);
        if (bullet) {
            flushParagraph();
            if (orderedOpen) {
                html.push('</ol>');
                orderedOpen = false;
            }
            if (!listOpen) {
                html.push('<ul>');
                listOpen = true;
            }
            html.push(`<li>${inlineMarkdown(bullet[1])}</li>`);
            continue;
        }

        const ordered = trimmed.match(/^\d+\.\s+(.+)$/);
        if (ordered) {
            flushParagraph();
            if (listOpen) {
                html.push('</ul>');
                listOpen = false;
            }
            if (!orderedOpen) {
                html.push('<ol>');
                orderedOpen = true;
            }
            html.push(`<li>${inlineMarkdown(ordered[1])}</li>`);
            continue;
        }

        paragraph.push(trimmed);
    }

    flushParagraph();
    closeLists();
    return html.join('');
}

function inlineMarkdown(text) {
    return escapeHtml(text)
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
}

function updateLLMMode(status) {
    const modeText = status.mode === 'real' ? `真实模型 ${status.model || ''}` : '模拟模式';
    setText('aiModeBadge', status.available === false ? '不可用' : modeText);
    setText('aiModeText', modeText);
}

function updateAIProgress(percent, message) {
    const fill = document.getElementById('aiProcessFill');
    if (fill) fill.style.width = `${percent}%`;
    setText('aiProcessText', `${percent}%`);
    setText('aiProcessMessage', message);
}

function compactText(text, maxLength) {
    const normalized = String(text).replace(/\s+/g, ' ').trim();
    return normalized.length > maxLength ? `${normalized.slice(0, maxLength)}...` : normalized;
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function setVisible(id, visible) {
    const el = document.getElementById(id);
    if (el) el.style.display = visible ? 'block' : 'none';
}

function setDisabled(id, disabled) {
    const el = document.getElementById(id);
    if (el) el.disabled = disabled;
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

window.TraceEye = window.TraceEye || {};
window.TraceEye.loadAIData = loadAIData;

if (document.getElementById('page-ai')) {
    initAIPage();
    setTimeout(() => window.TraceEye?.loadPageData?.('ai'), 0);
}
