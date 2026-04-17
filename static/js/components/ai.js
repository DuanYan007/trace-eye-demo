/**
 * AI 分析页面组件
 */

// 组件加载完成后的初始化
window.addEventListener('componentLoaded', (e) => {
    if (e.detail.name === 'ai') {
        initAIPage();
    }
});

/**
 * 初始化 AI 分析页面
 */
function initAIPage() {
    const analyzeBtn = document.getElementById('btnAIAnalyze');
    if (analyzeBtn) {
        analyzeBtn.addEventListener('click', executeAIAnalysis);
    }

    const reanalyzeBtn = document.getElementById('btnAIReanalyze');
    if (reanalyzeBtn) {
        reanalyzeBtn.addEventListener('click', executeAIAnalysis);
    }
}

/**
 * 加载 AI 分析页面数据
 * @param {Object} status - 系统状态
 * @param {Object} pageDataCache - 页面缓存数据
 */
async function loadAIData(status, pageDataCache) {
    if (status.steps_completed?.rules) {
        document.getElementById('aiInputEmpty').style.display = 'none';
        document.getElementById('aiInputFilled').style.display = 'block';

        try {
            const rulesData = await DataCache.get('rules');
            const data = rulesData?.data || {};

            const alertsEl = document.getElementById('aiInAlerts');
            if (alertsEl) alertsEl.textContent = Object.keys(data.alerts_by_rule || {}).length || 0;

            const bySeverity = data.by_severity || {};
            const highAlertsEl = document.getElementById('aiInHighAlerts');
            if (highAlertsEl) highAlertsEl.textContent = bySeverity.high || 0;

            // 显示操作区域
            const actionSection = document.getElementById('aiActionSection');
            if (actionSection) {
                actionSection.style.display = 'block';
            }

            // 如果已有分析结果，显示结果
            const aiData = pageDataCache || await DataCache.get('ai');
            if (aiData && !aiData.error) {
                displayAIResult(aiData);
            }
        } catch (e) {
            console.error('Load AI input data error:', e);
        }
    }
}

/**
 * 执行 AI 分析
 */
async function executeAIAnalysis() {
    try {
        // 显示进度区域
        document.getElementById('aiProgressSection').style.display = 'block';
        document.getElementById('aiResultsSection').style.display = 'none';
        document.getElementById('aiActionArea').style.display = 'none';
        document.getElementById('btnAIAnalyze').disabled = true;

        // 初始进度
        updateAIProgress(5, '检查 LLM 服务状态...');

        // 检查 LLM 状态
        const statusResponse = await apiGet('/llm/status');
        if (!statusResponse.available) {
            updateAIProgress(0, 'LLM 服务不可用');
            alert('LLM 服务不可用，将使用模拟模式生成分析结果');
        }

        updateAIProgress(10, '开始 AI 分析...');

        // 执行分析
        const response = await apiPost('/llm/analyze');
        updateAIProgress(100, '分析完成');

        setTimeout(() => {
            document.getElementById('aiProgressSection').style.display = 'none';
            document.getElementById('btnAIAnalyze').disabled = false;
            displayAIResult(response);
        }, 500);

    } catch (error) {
        document.getElementById('aiProgressSection').style.display = 'none';
        document.getElementById('btnAIAnalyze').disabled = false;
        alert(`AI 分析失败: ${error.message}`);
    }
}

/**
 * 显示 AI 分析结果
 */
function displayAIResult(result) {
    if (!result || result.error) {
        showEmptyState('aiResultsSection', '🤖', '暂无分析结果', '请先执行 AI 分析');
        return;
    }

    const resultsSection = document.getElementById('aiResultsSection');
    if (resultsSection) {
        resultsSection.style.display = 'block';
    }

    const story = result.attack_story || {};

    // 显示时间戳
    const timestampEl = document.getElementById('aiTimestamp');
    if (timestampEl) {
        timestampEl.textContent = result.analysis_time ? new Date(result.analysis_time).toLocaleString('zh-CN') : new Date().toLocaleString('zh-CN');
    }

    // 显示威胁概览
    const threatLevel = story.threat_level || 'unknown';
    const threatIconEl = document.getElementById('aiThreatIcon');
    const threatTextEl = document.getElementById('aiThreatText');
    const threatIcons = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢'
    };
    if (threatIconEl) threatIconEl.textContent = threatIcons[threatLevel] || '⚠️';
    if (threatTextEl) threatTextEl.textContent = story.threat_summary || '未知威胁';

    // 显示摘要
    const summaryEl = document.getElementById('aiSummary');
    if (summaryEl) summaryEl.textContent = story.attack_narrative?.substring(0, 200) + '...' || '暂无摘要';

    // 显示统计
    const stats = result.statistics || {};
    const originalCountEl = document.getElementById('aiOriginalCount');
    const filteredCountEl = document.getElementById('aiFilteredCount');
    const stagesCountEl = document.getElementById('aiStagesCount');
    const iocCountEl = document.getElementById('aiIocCount');

    if (originalCountEl) originalCountEl.textContent = stats.original_alerts || 0;
    if (filteredCountEl) filteredCountEl.textContent = stats.filtered_alerts || 0;
    if (stagesCountEl) stagesCountEl.textContent = story.attack_stages?.length || 0;
    if (iocCountEl) iocCountEl.textContent = story.iocs?.length || 0;

    // 显示攻击叙述
    const narrativeEl = document.getElementById('aiNarrative');
    if (narrativeEl) narrativeEl.innerHTML = (story.attack_narrative || '暂无攻击叙述').replace(/\n/g, '<br>');

    // 显示攻击阶段
    const stagesDiv = document.getElementById('aiStages');
    if (stagesDiv && story.attack_stages) {
        stagesDiv.innerHTML = story.attack_stages.map((stage, i) => `
            <div class="ai-stage-item">
                <div class="ai-stage-number">${i + 1}</div>
                <div class="ai-stage-content">
                    <div class="ai-stage-title">${escapeHtml(stage.stage || stage)}</div>
                    <div class="ai-stage-desc">${escapeHtml(stage.description || '')}</div>
                </div>
            </div>
        `).join('');
    }

    // 显示关键发现
    const findingsList = document.getElementById('aiFindings');
    if (findingsList && story.key_findings) {
        findingsList.innerHTML = story.key_findings.map(f => `<li>${escapeHtml(f)}</li>`).join('');
    }

    // 显示 IOC
    const iocList = document.getElementById('aiIocList');
    if (iocList && story.iocs) {
        iocList.innerHTML = story.iocs.map(ioc => `
            <div class="ai-ioc-item">
                <span class="ai-ioc-type">${escapeHtml(ioc.type)}:</span>
                <span class="ai-ioc-value">${escapeHtml(ioc.value)}</span>
            </div>
        `).join('');
    }

    // 显示处置建议
    const recommendationsList = document.getElementById('aiRecommendations');
    if (recommendationsList) {
        const recommendations = result.recommendations || story.recommendations || [];
        recommendationsList.innerHTML = recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('');
    }

    // 显示重新分析按钮区域
    const reanalyzeArea = document.getElementById('aiReanalyzeArea');
    if (reanalyzeArea) {
        reanalyzeArea.style.display = 'block';
    }
}

/**
 * 更新 AI 分析进度
 */
function updateAIProgress(percent, message) {
    const fill = document.getElementById('aiProcessFill');
    const text = document.getElementById('aiProcessText');
    const msg = document.getElementById('aiProcessMessage');

    if (fill) fill.style.width = `${percent}%`;
    if (text) text.textContent = `${percent}%`;
    if (msg) msg.textContent = message;
}

// 覆盖main.js中的占位函数
window.TraceEye = window.TraceEye || {};
window.TraceEye.loadAIData = loadAIData;
