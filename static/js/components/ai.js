/**
 * AI analysis page component.
 * Renders LLM output as a two-column Markdown report with a manual review flow.
 */

let currentAIReport = null;
let currentAIReviewMode = 'direct';
let currentLLMStatus = null;
let aiProgressTimer = null;
let aiProgressValue = 0;
let aiProgressStageIndex = 0;
const AI_ANALYSIS_TIMEOUT = 240000;
const AI_REVISE_TIMEOUT = 180000;

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
    document.getElementById('btnAITestConnection')?.addEventListener('click', testLLMConnection);
    document.querySelectorAll('#aiReviewModal .ai-review-mode').forEach(btn => {
        btn.addEventListener('click', () => setAIReviewMode(btn.dataset.mode || 'direct'));
    });
    document.getElementById('btnAIReviewLLMSend')?.addEventListener('click', sendAIReviewToLLM);
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
        window.localStorage.removeItem('trace_eye_ai_review_report');

        startAIProgress('检查 LLM 服务状态...');
        const statusResponse = await apiGet('/llm/status');
        updateLLMMode(statusResponse);

        updateAIProgress(15, '整理告警、关系图与攻击链上下文...');
        const model = document.getElementById('aiModelName')?.value?.trim();
        const response = await apiRequest('/llm/analyze', {
            method: 'POST',
            body: model ? { model } : {},
            timeout: AI_ANALYSIS_TIMEOUT
        });
        const report = normalizeAIResponse(response);

        finishAIProgress('分析完成');

        setVisible('aiProgressSection', false);
        setDisabled('btnAIAnalyze', false);
        displayAIResult(report);
    } catch (error) {
        stopAIProgress();
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
    const diagnosisMarkdown = isProbablyMojibake(result.diagnosis_markdown)
        ? buildDiagnosisMarkdown(result, story, report)
        : (result.diagnosis_markdown || buildDiagnosisMarkdown(result, story, report));
    const remediationMarkdown = isProbablyMojibake(result.remediation_markdown)
        ? buildRemediationMarkdown(story, recommendations)
        : (result.remediation_markdown || buildRemediationMarkdown(story, recommendations));

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

function isProbablyMojibake(text) {
    if (!text) return false;
    const value = String(text);
    const markers = ['�', '锟', '鏅', '鍒', '绯荤', '妫€', '€?', '鈫', '馃', '涓€', '/p>', '/h'];
    return markers.some(marker => value.includes(marker));
}

function readableText(text, fallback) {
    return text && !isProbablyMojibake(text) ? text : fallback;
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
    stopAIProgress();
    setVisible('aiProgressSection', false);
    setDisabled('btnAIAnalyze', false);

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
    const threatIcons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', unknown: '⚠️' };

    setText('aiTimestamp', new Date(currentAIReport.analyzed_at).toLocaleString('zh-CN'));
    setText('aiThreatIcon', threatIcons[threatLevel] || '⚠️');
    setText('aiThreatText', readableText(story.summary || story.threat_summary, 'LLM 已完成系统诊断'));
    renderInlineMarkdown(
        'aiSummary',
        story.attack_narrative && !isProbablyMojibake(story.attack_narrative)
            ? `**摘要:** ${compactText(story.attack_narrative, 220)}`
            : '**摘要:** 报告已生成，请查看左右两侧 Markdown 内容。'
    );
    setText('aiOriginalCount', stats.original_alerts || currentAIReport.original_alerts_count || 0);
    setText('aiFilteredCount', stats.filtered_alerts || currentAIReport.filtered_alerts_count || 0);
    setText('aiStagesCount', story.attack_stages?.length || 0);
    setText('aiIocCount', iocs.length || 0);

    renderAIReportCharts(currentAIReport);
    renderMarkdown('aiDiagnosisMarkdown', currentAIReport.diagnosis_markdown);
    renderMarkdown('aiRemediationMarkdown', currentAIReport.remediation_markdown);
    renderManualReview(currentAIReport.manual_review);
}

function renderAIReportCharts(report) {
    const container = document.getElementById('aiReportCharts');
    if (!container) return;

    const story = report.attack_story || {};
    const analysis = report.analysis_report || {};
    const stats = report.statistics || {};
    const severity = analysis.severity_summary || {};
    const stages = story.attack_stages || [];
    const iocs = story.ioc_list || story.iocs || [];
    const originalAlerts = Number(stats.original_alerts || report.original_alerts_count || 0);
    const filteredAlerts = Number(stats.filtered_alerts || report.filtered_alerts_count || analysis.total_filtered || 0);
    const severityRows = [
        { label: 'Critical', value: Number(severity.critical || 0), level: 'critical' },
        { label: 'High', value: Number(severity.high || 0), level: 'high' },
        { label: 'Medium', value: Number(severity.medium || 0), level: 'medium' },
        { label: 'Low', value: Number(severity.low || 0), level: 'low' }
    ];
    const maxSeverity = Math.max(1, ...severityRows.map(row => row.value));
    const maxAlerts = Math.max(1, originalAlerts, filteredAlerts);
    const iocTypes = countBy(iocs, ioc => readableText((ioc && ioc.type) || 'unknown', 'unknown'));
    const stageRows = stages.length
        ? stages.map((stage, index) => ({ label: readableText(stage.stage, `Stage ${index + 1}`), value: 1 }))
        : [{ label: 'No structured stage', value: 0 }];

    container.innerHTML = `
        <section class="ai-chart-card severity">
            <div class="ai-chart-title">
                <strong>告警严重度分布</strong>
                <span>按 LLM 降噪后告警统计</span>
            </div>
            <div class="ai-bar-list">
                ${severityRows.map(row => renderBarRow(row.label, row.value, maxSeverity, row.level)).join('')}
            </div>
        </section>

        <section class="ai-chart-card reduction">
            <div class="ai-chart-title">
                <strong>告警降噪效果</strong>
                <span>原始告警 / 降噪后告警</span>
            </div>
            <div class="ai-column-chart">
                ${renderColumn('原始', originalAlerts, maxAlerts, 'original')}
                ${renderColumn('降噪后', filteredAlerts, maxAlerts, 'filtered')}
            </div>
        </section>

        <section class="ai-chart-card stages">
            <div class="ai-chart-title">
                <strong>攻击阶段覆盖</strong>
                <span>${stages.length || 0} 个阶段</span>
            </div>
            <div class="ai-stage-chart">
                ${stageRows.map((row, index) => `
                    <div class="ai-stage-node ${row.value ? 'active' : ''}">
                        <b>${index + 1}</b>
                        <span title="${escapeHtml(row.label)}">${escapeHtml(row.label)}</span>
                    </div>
                `).join('')}
            </div>
        </section>

        <section class="ai-chart-card ioc">
            <div class="ai-chart-title">
                <strong>IOC 类型分布</strong>
                <span>${iocs.length || 0} 个指标</span>
            </div>
            <div class="ai-donut-wrap">
                ${renderDonut(iocTypes)}
                <div class="ai-ioc-legend">
                    ${Object.entries(iocTypes).length
                        ? Object.entries(iocTypes).map(([type, count]) => `<span><i></i>${escapeHtml(type)} <b>${count}</b></span>`).join('')
                        : '<span><i></i>暂无 IOC <b>0</b></span>'}
                </div>
            </div>
        </section>
    `;
}

function renderBarRow(label, value, max, level) {
    const width = Math.max(value > 0 ? 8 : 0, Math.round((value / max) * 100));
    return `
        <div class="ai-bar-row ${level}">
            <span class="bar-label">${escapeHtml(label)}</span>
            <span class="bar-track"><i style="width:${width}%"></i></span>
            <b>${value}</b>
        </div>
    `;
}

function renderColumn(label, value, max, type) {
    const height = Math.max(value > 0 ? 10 : 2, Math.round((value / max) * 100));
    return `
        <div class="ai-column ${type}">
            <div class="ai-column-bar"><i style="height:${height}%"></i></div>
            <b>${value}</b>
            <span>${escapeHtml(label)}</span>
        </div>
    `;
}

function renderDonut(counts) {
    const entries = Object.entries(counts);
    const total = entries.reduce((sum, [, count]) => sum + count, 0);
    if (!total) {
        return '<div class="ai-donut empty" style="--donut: conic-gradient(rgba(148,163,184,.3) 0 100%)"><b>0</b><span>IOC</span></div>';
    }
    const colors = ['#60a5fa', '#34d399', '#f59e0b', '#fb7185', '#a78bfa'];
    let cursor = 0;
    const segments = entries.map(([, count], index) => {
        const start = cursor;
        cursor += (count / total) * 100;
        return `${colors[index % colors.length]} ${start}% ${cursor}%`;
    });
    return `<div class="ai-donut" style="--donut: conic-gradient(${segments.join(', ')})"><b>${total}</b><span>IOC</span></div>`;
}

function countBy(items, getKey) {
    return (items || []).reduce((acc, item) => {
        const key = getKey(item);
        acc[key] = (acc[key] || 0) + 1;
        return acc;
    }, {});
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
        '## 威胁等级',
        `- 当前等级: **${story.threat_level || 'unknown'}**`,
        `- 摘要: ${readableText(story.summary || story.threat_summary, '暂无摘要')}`,
        '',
        '## 告警概览',
        `- 原始告警: **${result.original_alerts_count || stats.original_alerts || 0}**`,
        `- 降噪后告警: **${result.filtered_alerts_count || stats.filtered_alerts || report.total_filtered || 0}**`,
        `- 高危告警: **${severity.high || 0}**`,
        `- 中危告警: **${severity.medium || 0}**`,
        '',
        '## 主要问题',
        ...(findings.length ? findings.map(item => `- ${readableText(item, '存在可疑行为，需要专家复核原始证据。')}`) : ['- 未提取到结构化关键问题，建议专家检查原始告警与攻击链。']),
        '',
        '## 攻击阶段证据',
        ...(stages.length ? stages.map((stage, index) => {
            const evidence = (stage.evidence || []).map(item => `  - 证据: ${readableText(item, '证据内容需复核')}`).join('\n');
            const stageName = readableText(stage.stage, `阶段 ${index + 1}`);
            const description = readableText(stage.description, '暂无描述');
            return `${index + 1}. **${stageName}**: ${description}${evidence ? `\n${evidence}` : ''}`;
        }) : ['- 暂无明确攻击阶段。']),
        '',
        '## IOC 指标',
        ...(iocs.length ? iocs.map(ioc => `- \`${readableText(ioc.type, 'unknown')}\`: ${readableText(ioc.value, '-')} ${ioc.description ? `- ${readableText(ioc.description, '暂无描述')}` : ''}`) : ['- 暂无可提取 IOC。'])
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
        ...(recommendations.length ? recommendations.map(item => `- ${readableText(item, '建议专家复核后处置。')}`) : [
            '- 隔离受影响主机，避免横向移动继续扩散。',
            '- 冻结可疑账户并轮换相关凭据。',
            '- 备份关键日志、进程列表、网络连接和可疑文件样本。'
        ]),
        '',
        '## 分阶段修复',
        ...(stages.length ? stages.map((stage, index) => `- **${readableText(stage.stage, `阶段 ${index + 1}`)}**: ${readableText(stage.description, '复核该阶段关联资产，并补充检测规则。')}`) : [
            '- 对告警涉及的主机、进程、文件和网络连接进行人工复核。',
            '- 将误报和真实威胁分别沉淀为白名单与新检测规则。'
        ]),
        '',
        '## IOC 封禁与监控',
        ...(iocs.length ? iocs.map(ioc => `- 将 \`${readableText(ioc.value, '-')}\` 加入 ${readableText(ioc.type, 'IOC')} 监控/阻断列表。`) : [
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
    document.getElementById('aiReviewLLMInput').value = '';
    setAIReviewMode(currentAIReviewMode || 'direct');
    setText('aiReviewLLMStatus', '');
    document.getElementById('aiReviewModal').classList.add('active');
}

function closeAIReviewModal() {
    document.getElementById('aiReviewModal')?.classList.remove('active');
}

function saveAIReviewEdits() {
    if (!currentAIReport) return;
    const reviewTitle = currentAIReviewMode === 'llm' ? 'Expert + LLM review completed' : 'Expert review completed';
    const reviewReason = document.getElementById('aiReviewNoteInput').value
        || (currentAIReviewMode === 'llm' ? 'LLM revised the report according to expert guidance.' : 'Expert confirmed and saved the report edits.');
    currentAIReport = {
        ...currentAIReport,
        diagnosis_markdown: document.getElementById('aiReviewDiagnosisInput').value,
        remediation_markdown: document.getElementById('aiReviewRemediationInput').value,
        review_note: reviewReason,
        review_mode: currentAIReviewMode,
        reviewed_at: new Date().toISOString(),
        manual_review: {
            required: false,
            title: reviewTitle,
            reason: reviewReason
        }
    };
    window.localStorage.setItem('trace_eye_ai_review_report', JSON.stringify(currentAIReport));
    displayAIResult(currentAIReport);
    closeAIReviewModal();
}

function setAIReviewMode(mode) {
    currentAIReviewMode = mode === 'llm' ? 'llm' : 'direct';
    document.querySelectorAll('#aiReviewModal .ai-review-mode').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.mode === currentAIReviewMode);
    });
    document.getElementById('aiReviewDirectPanel')?.classList.toggle('active', currentAIReviewMode === 'direct');
    document.getElementById('aiReviewLLMPanel')?.classList.toggle('active', currentAIReviewMode === 'llm');
}

async function sendAIReviewToLLM() {
    if (!currentAIReport) return;
    const input = document.getElementById('aiReviewLLMInput');
    const expertMessage = input?.value.trim();
    if (!expertMessage) {
        alert('请输入专家建议后再发送给 LLM。');
        return;
    }

    appendAIReviewChat('expert', expertMessage);
    setText('aiReviewLLMStatus', 'LLM 正在根据专家建议修订...');
    setDisabled('btnAIReviewLLMSend', true);

    try {
        const response = await apiRequest('/llm/revise', {
            method: 'POST',
            body: {
                report: {
                    ...currentAIReport,
                    diagnosis_markdown: document.getElementById('aiReviewDiagnosisInput')?.value || currentAIReport.diagnosis_markdown,
                    remediation_markdown: document.getElementById('aiReviewRemediationInput')?.value || currentAIReport.remediation_markdown
                },
                expert_message: expertMessage
            },
            timeout: AI_REVISE_TIMEOUT
        });
        const revised = normalizeAIResponse(response.result || response);
        currentAIReport = {
            ...currentAIReport,
            ...revised,
            review_mode: 'llm',
            review_note: revised.review_note || expertMessage
        };
        document.getElementById('aiReviewDiagnosisInput').value = currentAIReport.diagnosis_markdown || '';
        document.getElementById('aiReviewRemediationInput').value = currentAIReport.remediation_markdown || '';
        document.getElementById('aiReviewNoteInput').value = currentAIReport.review_note || '';
        window.localStorage.setItem('trace_eye_ai_review_report', JSON.stringify(currentAIReport));
        displayAIResult(currentAIReport);
        appendAIReviewChat('assistant', currentAIReport.review_note || '已完成智能修订，新的报告已更新到页面。');
        setText('aiReviewLLMStatus', '已生成智能修订，可继续对话或保存复核结果。');
        if (input) input.value = '';
    } catch (error) {
        appendAIReviewChat('assistant', `智能修订失败：${error.message}`);
        setText('aiReviewLLMStatus', '智能修订失败，请检查 LLM 配置或重试。');
    } finally {
        setDisabled('btnAIReviewLLMSend', false);
    }
}

function appendAIReviewChat(role, text) {
    const log = document.getElementById('aiReviewChatLog');
    if (!log) return;
    const item = document.createElement('div');
    item.className = `ai-chat-message ${role === 'expert' ? 'expert' : 'assistant'}`;
    item.innerHTML = `
        <strong>${role === 'expert' ? '专家' : 'LLM'}</strong>
        <p>${escapeHtml(text)}</p>
    `;
    log.appendChild(item);
    log.scrollTop = log.scrollHeight;
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
            const title = heading[2];
            html.push(`<h${level}>${inlineMarkdown(title)}</h${level}>`);
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
    currentLLMStatus = status || {};
    const modeText = status.mode === 'real' ? `真实模型 ${status.model || ''}` : '演示模式';
    setText('aiModeBadge', status.available === false ? '不可用' : modeText);
    setText('aiModeText', modeText);

    const modelInput = document.getElementById('aiModelName');
    if (modelInput && !modelInput.value) {
        modelInput.value = status.model || (status.provider === 'deepseek' ? 'deepseek-v4' : '');
    }

    const connectionText = status.available === false
        ? (status.configured ? '服务不可用' : '未配置 API Key')
        : (status.mode === 'real' ? '已读取当前模型配置' : '演示模式，无需连接测试');
    setText('aiConnectionStatus', connectionText);
}

async function testLLMConnection() {
    const modelInput = document.getElementById('aiModelName');
    const model = modelInput?.value?.trim() || currentLLMStatus?.model || '';

    if (!model) {
        alert('请先填写模型名称。');
        modelInput?.focus();
        return;
    }

    setDisabled('btnAITestConnection', true);
    setText('aiConnectionStatus', '正在测试连接...');

    try {
        const result = await apiPost('/llm/test', { model });
        updateLLMMode(result.status || {
            available: result.success,
            configured: result.configured,
            provider: result.provider,
            model: result.model,
            mock_mode: false,
            mode: result.mode || 'real'
        });
        setText('aiConnectionStatus', result.message || '连接测试通过');
    } catch (error) {
        setText('aiConnectionStatus', `连接失败: ${error.message}`);
    } finally {
        setDisabled('btnAITestConnection', false);
    }
}

function updateAIProgress(percent, message) {
    aiProgressValue = Math.max(0, Math.min(100, Number(percent) || 0));
    const fill = document.getElementById('aiProcessFill');
    if (fill) fill.style.width = `${aiProgressValue}%`;
    setText('aiProcessText', `${Math.round(aiProgressValue)}%`);
    setText('aiProcessMessage', message);
}

function startAIProgress(initialMessage) {
    stopAIProgress();
    aiProgressValue = 5;
    aiProgressStageIndex = 0;
    updateAIProgress(aiProgressValue, initialMessage);

    const stages = [
        { at: 18, message: '整理告警、关系图与攻击链上下文...' },
        { at: 32, message: '压缩证据链并生成 LLM 输入...' },
        { at: 48, message: '等待 DeepSeek 返回诊断报告...' },
        { at: 64, message: '解析 Markdown 报告与修复建议...' },
        { at: 78, message: '生成报告图表与复核信息...' },
        { at: 88, message: '即将完成，请稍候...' }
    ];

    aiProgressTimer = window.setInterval(() => {
        if (aiProgressValue >= 88) return;

        const nextStage = stages[aiProgressStageIndex];
        const increment = aiProgressValue < 48 ? 2 : aiProgressValue < 78 ? 1 : 0.4;
        const nextValue = Math.min(88, aiProgressValue + increment);
        const currentMessage = document.getElementById('aiProcessMessage')?.textContent || '正在分析...';

        if (nextStage && nextValue >= nextStage.at) {
            updateAIProgress(nextStage.at, nextStage.message);
            aiProgressStageIndex += 1;
        } else {
            updateAIProgress(nextValue, currentMessage);
        }
    }, 900);
}

function stopAIProgress() {
    if (aiProgressTimer) {
        window.clearInterval(aiProgressTimer);
        aiProgressTimer = null;
    }
}

function finishAIProgress(message) {
    stopAIProgress();
    updateAIProgress(100, message || '分析完成');
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
