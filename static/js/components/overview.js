/**
 * 总览页组件
 * Trace-Eye APT 威胁检测系统总览
 */

// ==================== 全局变量 ====================
let overviewCharts = {};
let overviewData = {
    status: null,
    overview: null
};

// ==================== 初始化 ====================
document.addEventListener('DOMContentLoaded', () => {
    initOverviewPage();
});

async function initOverviewPage() {
    bindOverviewEvents();
    await loadOverviewData();
    startActivityPolling();
}

// ==================== 事件绑定 ====================
function bindOverviewEvents() {
    // 快速操作按钮
    document.getElementById('btnGenerateData')?.addEventListener('click', handleGenerateData);
    document.getElementById('btnUploadLogs')?.addEventListener('click', handleUploadLogs);
    document.getElementById('btnRunAnalysis')?.addEventListener('click', handleRunAnalysis);
    document.getElementById('btnExportReport')?.addEventListener('click', handleExportReport);

    // 图表类型切换
    document.querySelectorAll('.chart-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.chart-btn').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            updateTimelineChart(e.target.dataset.type);
        });
    });
}

// ==================== 数据加载 ====================
async function loadOverviewData() {
    try {
        // 使用专用的总览API
        const response = await fetch('/api/overview');
        if (!response.ok) throw new Error('获取总览数据失败');

        const data = await response.json();
        overviewData.overview = data;

        // 同时获取系统状态（用于进度条）
        const status = await getSystemStatus();
        overviewData.status = status;

        // 更新UI
        updateAllSections(data);

    } catch (error) {
        console.error('加载总览数据失败:', error);
        showOverviewError(error.message);
    }
}

async function getSystemStatus() {
    const response = await fetch('/api/status');
    if (!response.ok) throw new Error('获取系统状态失败');
    return await response.json();
}

// ==================== UI更新 ====================
function updateAllSections(data) {
    data = data || overviewData.overview || {};
    updateThreatGauge(data.threat_level);
    updateSummaryCards(data.summary);
    updateProgressSteps(data.progress);
    updateEventStats(data.events);
    updateGraphStats(data.graph);
    updateRulesStats(data.rules);
    updateChainsStats(data.chains);
    initCharts(data);
    updateTopThreats(data.threat);
    updateAlertsTimeline(data.recent_alerts);
    updateAttackMatrix(data.attack_matrix);
    updateActivityLog();
}

// 威胁等级仪表盘
function updateThreatGauge(threatLevel) {
    threatLevel = threatLevel || 'unknown';
    const levelText = document.getElementById('overviewThreatLevel');
    const gaugeFill = document.getElementById('gaugeFill');
    const gaugeNeedle = document.getElementById('gaugeNeedle');

    const levelConfig = {
        'critical': { text: '严重', percent: 100, angle: 90 },
        'high': { text: '高危', percent: 75, angle: 67.5 },
        'medium': { text: '中危', percent: 50, angle: 45 },
        'low': { text: '低危', percent: 25, angle: 22.5 },
        'benign': { text: '正常', percent: 0, angle: -90 },
        'unknown': { text: '--', percent: 0, angle: -90 }
    };

    const config = levelConfig[threatLevel] || levelConfig['unknown'];

    if (levelText) levelText.textContent = config.text;

    // 更新仪表盘填充
    if (gaugeFill) {
        const offset = 251.2 * (1 - config.percent / 100);
        gaugeFill.style.strokeDashoffset = offset;
    }

    // 更新指针
    if (gaugeNeedle) {
        gaugeNeedle.style.transform = `translate(100px, 100px) rotate(${config.angle}deg)`;
    }
}

// 摘要卡片
function updateSummaryCards(summary) {
    summary = summary || {};

    animateValue('overviewCriticalCount', 0, summary.critical || 0, 1000);
    animateValue('overviewHighCount', 0, summary.high || 0, 1000);
    animateValue('overviewMediumCount', 0, summary.medium || 0, 1000);
    animateValue('overviewAlertsCount', 0, summary.alerts || 0, 1000);

    // 绘制趋势图
    drawTrendChart('criticalTrendCanvas', [summary.critical || 0]);
    drawTrendChart('highTrendCanvas', [summary.high || 0]);
    drawTrendChart('mediumTrendCanvas', [summary.medium || 0]);
    drawTrendChart('alertsTrendCanvas', [summary.alerts || 0]);
}

// 进度步骤
function updateProgressSteps(progress) {
    progress = progress || overviewData.status?.steps_status || {};

    // 支持两种数据格式
    const stepsData = progress.steps || progress;
    const steps = ['upload', 'extract', 'graph', 'rules', 'threat', 'relations', 'chains', 'ai'];

    let completedCount = 0;

    steps.forEach((step, index) => {
        const stepEl = document.getElementById(`progressStep${step.charAt(0).toUpperCase() + step.slice(1)}`);
        const connector = stepEl?.nextElementSibling;

        if (stepEl) {
            stepEl.classList.remove('completed', 'active', 'running');

            const stepStatus = stepsData[step];
            if (stepStatus?.completed) {
                stepEl.classList.add('completed');
                stepEl.querySelector('.status-badge').textContent = '已完成';
                if (connector?.classList.contains('progress-connector')) {
                    connector.classList.add('completed');
                }
                completedCount++;
            } else if (stepStatus?.running) {
                stepEl.classList.add('running');
                stepEl.querySelector('.status-badge').textContent = '进行中';
            } else if (index === 0 || stepsData[steps[index - 1]]?.completed) {
                stepEl.classList.add('active');
                stepEl.querySelector('.status-badge').textContent = '待处理';
            } else {
                stepEl.querySelector('.status-badge').textContent = '等待中';
            }
        }
    });

    const percent = Math.round((completedCount / steps.length) * 100);
    document.getElementById('overviewProgressPercent').textContent = `${percent}%`;
}

// 事件统计
function updateEventStats(events) {
    events = events || {};

    const total = events.total || 0;
    const byType = events.by_type || {};

    document.getElementById('overviewTotalEvents').textContent = formatNumber(total);
    document.getElementById('processCount').textContent = formatNumber(byType.process || 0);
    document.getElementById('fileCount').textContent = formatNumber(byType.file || 0);
    document.getElementById('networkCount').textContent = formatNumber(byType.network || 0);

    // 更新进度条
    const processPercent = total > 0 ? ((byType.process || 0) / total * 100) : 0;
    const filePercent = total > 0 ? ((byType.file || 0) / total * 100) : 0;
    const networkPercent = total > 0 ? ((byType.network || 0) / total * 100) : 0;

    setTimeout(() => {
        document.getElementById('processBar').style.width = `${processPercent}%`;
        document.getElementById('fileBar').style.width = `${filePercent}%`;
        document.getElementById('networkBar').style.width = `${networkPercent}%`;
    }, 100);
}

// 图统计
function updateGraphStats(graph) {
    graph = graph || {};

    document.getElementById('overviewNodeCount').textContent = formatNumber(graph.nodes || 0);
    document.getElementById('overviewEdgeCount').textContent = formatNumber(graph.edges || 0);
    document.getElementById('overviewAvgDegree').textContent = (graph.avg_degree || 0).toFixed(2);
    document.getElementById('overviewDensity').textContent = (graph.density || 0).toExponential(2);

    // 绘制节点类型饼图
    drawNodeTypePie(graph.node_types || {});
}

// 规则统计
function updateRulesStats(rules) {
    rules = rules || {};
    const byCategory = rules.by_category || {};

    document.getElementById('ruleFileCount').textContent = byCategory.file || 0;
    document.getElementById('ruleProcessCount').textContent = byCategory.process || 0;
    document.getElementById('ruleNetworkCount').textContent = byCategory.network || 0;
    document.getElementById('ruleSequenceCount').textContent = byCategory.sequence || 0;
    document.getElementById('ruleTemporalCount').textContent = byCategory.temporal || 0;
}

// 攻击链统计
function updateChainsStats(chains) {
    chains = chains || {};

    document.getElementById('overviewChainsCount').textContent = chains.total || 0;

    const typesList = document.getElementById('attackTypesList');
    typesList.innerHTML = '';

    const byType = chains.by_type || {};
    Object.entries(byType).forEach(([type, count]) => {
        const tag = document.createElement('span');
        tag.className = 'attack-type-tag';
        tag.textContent = `${type}: ${count}`;
        typesList.appendChild(tag);
    });

    if (Object.keys(byType).length === 0) {
        typesList.innerHTML = '<span class="attack-type-tag">暂无攻击链</span>';
    }
}

// ==================== 图表初始化 ====================
function initCharts(data) {
    data = data || overviewData.overview || {};
    initTimelineChart(data.events);
    initSeverityPieChart(data.rules);
    initThreatLevelChart(data.threat);
    initRuleCategoryChart(data.rules);
}

// 事件时间分布图
function initTimelineChart(events) {
    events = events || {};
    const timeline = events.timeline || { hours: [], counts: [] };

    const chart = echarts.init(document.getElementById('eventTimelineChart'));

    // 如果没有数据，生成默认24小时数据
    let hours = timeline.hours;
    let counts = timeline.counts;

    if (!hours || hours.length === 0) {
        hours = [];
        counts = [];
        for (let i = 0; i < 24; i++) {
            hours.push(`${i}:00`);
            counts.push(Math.floor(Math.random() * 500) + 100);
        }
    }

    const option = {
        tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'cross' }
        },
        grid: {
            left: '3%',
            right: '4%',
            bottom: '3%',
            containLabel: true
        },
        xAxis: {
            type: 'category',
            boundaryGap: false,
            data: hours
        },
        yAxis: {
            type: 'value',
            axisLabel: { formatter: '{value}' }
        },
        series: [{
            name: '事件数',
            type: 'line',
            smooth: true,
            data: counts,
            areaStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                    { offset: 0, color: 'rgba(33, 150, 243, 0.3)' },
                    { offset: 1, color: 'rgba(33, 150, 243, 0.05)' }
                ])
            },
            lineStyle: { color: '#2196F3', width: 2 },
            itemStyle: { color: '#2196F3' }
        }]
    };

    chart.setOption(option);
    overviewCharts.timeline = chart;
}

// 告警严重程度饼图
function initSeverityPieChart(rules) {
    rules = rules || {};
    const bySeverity = rules.by_severity || {};

    const chart = echarts.init(document.getElementById('severityPieChart'));

    const option = {
        tooltip: {
            trigger: 'item',
            formatter: '{b}: {c} ({d}%)'
        },
        legend: {
            orient: 'vertical',
            right: '10%',
            top: 'center'
        },
        series: [{
            type: 'pie',
            radius: ['40%', '70%'],
            center: ['40%', '50%'],
            data: [
                { value: bySeverity.high || 0, name: '高危', itemStyle: { color: '#f44336' } },
                { value: bySeverity.medium || 0, name: '中危', itemStyle: { color: '#ff9800' } },
                { value: bySeverity.low || 0, name: '低危', itemStyle: { color: '#4CAF50' } }
            ],
            label: {
                formatter: '{b}\n{d}%'
            }
        }]
    };

    chart.setOption(option);
    overviewCharts.severity = chart;
}

// 威胁等级分布图
function initThreatLevelChart(threat) {
    threat = threat || {};
    const byLevel = threat.by_level || {};

    const chart = echarts.init(document.getElementById('threatLevelChart'));

    const option = {
        tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'shadow' }
        },
        grid: {
            left: '3%',
            right: '4%',
            bottom: '3%',
            containLabel: true
        },
        xAxis: {
            type: 'value'
        },
        yAxis: {
            type: 'category',
            data: ['严重', '高危', '中危', '低危', '正常']
        },
        series: [{
            type: 'bar',
            data: [
                { value: byLevel.critical || 0, itemStyle: { color: '#d32f2f' } },
                { value: byLevel.high || 0, itemStyle: { color: '#f57c00' } },
                { value: byLevel.medium || 0, itemStyle: { color: '#ffc107' } },
                { value: byLevel.low || 0, itemStyle: { color: '#4CAF50' } },
                { value: byLevel.benign || 0, itemStyle: { color: '#9e9e9e' } }
            ],
            barWidth: '60%',
            label: {
                show: true,
                position: 'right',
                formatter: '{c}'
            }
        }]
    };

    chart.setOption(option);
    overviewCharts.threatLevel = chart;
}

// 规则类别触发统计
function initRuleCategoryChart(rules) {
    rules = rules || {};
    const byCategory = rules.by_category || {};

    const categoryNames = {
        'file': '文件异常',
        'process': '进程异常',
        'network': '网络异常',
        'sequence': '行为序列',
        'temporal': '时序异常'
    };

    const chart = echarts.init(document.getElementById('ruleCategoryChart'));

    const categories = Object.keys(byCategory);
    const data = categories.map(cat => byCategory[cat] || 0);

    const option = {
        tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'shadow' }
        },
        grid: {
            left: '3%',
            right: '4%',
            bottom: '3%',
            containLabel: true
        },
        xAxis: {
            type: 'value'
        },
        yAxis: {
            type: 'category',
            data: categories.map(c => categoryNames[c] || c)
        },
        series: [{
            type: 'bar',
            data: data,
            itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
                    { offset: 0, color: '#667eea' },
                    { offset: 1, color: '#764ba2' }
                ])
            },
            barWidth: '50%',
            label: {
                show: true,
                position: 'right',
                formatter: '{c}'
            }
        }]
    };

    chart.setOption(option);
    overviewCharts.ruleCategory = chart;
}

// ==================== 高风险节点列表 ====================
function updateTopThreats(threat) {
    threat = threat || {};
    const nodeList = document.getElementById('topThreatsList');
    const topNodes = threat.top_nodes || [];

    if (topNodes.length === 0) {
        nodeList.innerHTML = '<div class="empty-message">暂无威胁数据</div>';
        return;
    }

    nodeList.innerHTML = '';

    topNodes.forEach((nodeData, index) => {
        const item = document.createElement('div');
        item.className = 'threat-item';

        const rank = index + 1;
        const rankClass = rank <= 3 ? `top${rank}` : '';
        const scorePercent = (nodeData.threat_score || 0) * 100;

        item.innerHTML = `
            <div class="threat-rank ${rankClass}">${rank}</div>
            <div class="threat-info">
                <div class="threat-name">${escapeHtml(nodeData.node_id)}</div>
                <div class="threat-type">${nodeData.classification || 'unknown'}</div>
            </div>
            <div class="threat-score">
                <div class="score-bar">
                    <div class="score-fill" style="width: ${scorePercent}%"></div>
                </div>
                <div class="score-value">${(nodeData.threat_score * 100).toFixed(1)}%</div>
            </div>
        `;

        nodeList.appendChild(item);
    });
}

// ==================== 告警时间线 ====================
function updateAlertsTimeline(recentAlerts) {
    recentAlerts = recentAlerts || [];
    const timeline = document.getElementById('alertsTimeline');

    timeline.innerHTML = '';

    recentAlerts.forEach(alert => {
        const item = document.createElement('div');
        item.className = 'timeline-item';

        const severity = alert.rule?.severity || 'low';
        const time = formatTime(alert.timestamp);
        const ruleId = alert.rule?.rule_id || '';
        const message = alert.message || ruleId;

        item.innerHTML = `
            <div class="timeline-dot ${severity}"></div>
            <div class="timeline-content">
                <div class="timeline-time">${time}</div>
                <div class="timeline-alert ${severity}">
                    <span class="alert-rule">${ruleId}</span>
                    <span class="alert-message">${escapeHtml(message)}</span>
                </div>
            </div>
        `;

        timeline.appendChild(item);
    });

    if (recentAlerts.length === 0) {
        timeline.innerHTML = '<div class="empty-message">暂无告警</div>';
    }
}

// ==================== ATT&CK 战术矩阵 ====================
function updateAttackMatrix(attackMatrix) {
    attackMatrix = attackMatrix || {};
    const matrix = document.getElementById('attackMatrix');

    // 更新矩阵显示
    let activeCount = 0;
    matrix.querySelectorAll('.matrix-tactic').forEach(tacticEl => {
        const tactic = tacticEl.dataset.tactic;
        const count = attackMatrix[tactic] || 0;
        const countEl = tacticEl.querySelector('.tactic-count');

        countEl.textContent = count;

        if (count > 0) {
            tacticEl.classList.add('active');
            activeCount++;
        } else {
            tacticEl.classList.remove('active');
        }
    });

    // 更新覆盖数
    document.getElementById('matrixCoverage').textContent = activeCount;
}

// ==================== 活动日志 ====================
const activityLogs = [];

function updateActivityLog() {
    const logList = document.getElementById('activityLogList');
    logList.innerHTML = '';

    activityLogs.slice(0, 10).forEach(log => {
        const item = document.createElement('div');
        item.className = 'activity-item';
        item.innerHTML = `
            <span class="activity-time">${log.time}</span>
            <span class="activity-message">${escapeHtml(log.message)}</span>
        `;
        logList.appendChild(item);
    });
}

function addActivityLog(message) {
    const now = new Date();
    const time = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`;

    activityLogs.unshift({ time, message });
    if (activityLogs.length > 50) activityLogs.pop();

    updateActivityLog();
}

function startActivityPolling() {
    // 监听系统状态变化
    setInterval(async () => {
        try {
            const status = await getSystemStatus();
            const oldStatus = overviewData.status;

            // 检查步骤状态变化
            Object.entries(status.steps_status || {}).forEach(([step, stepInfo]) => {
                const oldStep = oldStatus?.steps_status?.[step];
                if (oldStep?.completed !== stepInfo.completed && stepInfo.completed) {
                    addActivityLog(`步骤 "${getStepName(step)}" 已完成`);
                }
                if (oldStep?.running !== stepInfo.running && stepInfo.running) {
                    addActivityLog(`步骤 "${getStepName(step)}" 开始执行`);
                }
            });

            overviewData.status = status;
            updateProgressSteps();

        } catch (error) {
            console.error('状态轮询错误:', error);
        }
    }, 5000);

    addActivityLog('系统监控已启动');
}

function updateTopStats(status) {
    // 可以在这里更新顶部统计栏
}

// ==================== 快速操作 ====================
async function handleGenerateData() {
    addActivityLog('开始生成测试数据...');
    try {
        const response = await fetch('/api/generate', { method: 'POST' });
        if (!response.ok) throw new Error('生成数据失败');
        addActivityLog('测试数据生成成功');
        await loadOverviewData();
    } catch (error) {
        addActivityLog('生成数据失败: ' + error.message);
    }
}

async function handleUploadLogs() {
    // 跳转到上传页面
    window.location.hash = '#page-upload';
}

async function handleRunAnalysis() {
    addActivityLog('开始运行全部分析...');
    // 实现顺序执行所有步骤
    const steps = ['extract', 'graph', 'rules', 'threat', 'relations', 'chains'];
    for (const step of steps) {
        try {
            addActivityLog(`执行步骤: ${getStepName(step)}`);
            const response = await fetch(`/api/step/${step}`, { method: 'POST' });
            if (!response.ok) throw new Error(`${step} 失败`);
            await response.json();
        } catch (error) {
            addActivityLog(`步骤 ${step} 失败: ${error.message}`);
            return;
        }
    }
    addActivityLog('全部分析完成');
    await loadOverviewData();
}

async function handleExportReport() {
    addActivityLog('导出报告...');
    try {
        const response = await fetch('/api/download/analysis');
        if (!response.ok) throw new Error('导出失败');
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'trace-eye-report.json';
        a.click();
        URL.revokeObjectURL(url);
        addActivityLog('报告导出成功');
    } catch (error) {
        addActivityLog('导出失败: ' + error.message);
    }
}

// ==================== 工具函数 ====================
function animateValue(elementId, start, end, duration) {
    const element = document.getElementById(elementId);
    if (!element) return;

    const range = end - start;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // 使用 easeOutQuart 缓动
        const easeProgress = 1 - Math.pow(1 - progress, 4);
        const current = Math.round(start + range * easeProgress);

        element.textContent = formatNumber(current);

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}

function formatNumber(num) {
    if (num >= 10000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toLocaleString();
}

function formatTime(timestamp) {
    if (!timestamp) return '--';
    const date = new Date(timestamp);
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const day = date.getDate().toString().padStart(2, '0');
    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    return `${month}-${day} ${hours}:${minutes}`;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function getStepName(step) {
    const names = {
        'upload': '数据准备',
        'extract': '事件提取',
        'graph': '关系图构建',
        'rules': '规则检测',
        'threat': '威胁检测',
        'relations': '关系挖掘',
        'chains': '攻击链重建',
        'ai': 'AI分析'
    };
    return names[step] || step;
}

function showOverviewError(message) {
    console.error('Overview Error:', message);
}

// ==================== Canvas 绘图 ====================
function drawTrendChart(canvasId, data) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;

    ctx.clearRect(0, 0, width, height);

    if (data.length === 0) return;

    const max = Math.max(...data, 1);
    const points = data.map((val, i) => ({
        x: (i / (data.length - 1 || 1)) * width,
        y: height - (val / max) * height
    }));

    // 绘制填充
    ctx.beginPath();
    ctx.moveTo(points[0].x, height);
    points.forEach(p => ctx.lineTo(p.x, p.y));
    ctx.lineTo(points[points.length - 1].x, height);
    ctx.closePath();

    const gradient = ctx.createLinearGradient(0, 0, 0, height);
    gradient.addColorStop(0, 'rgba(255,255,255,0.3)');
    gradient.addColorStop(1, 'rgba(255,255,255,0)');
    ctx.fillStyle = gradient;
    ctx.fill();

    // 绘制线条
    ctx.beginPath();
    points.forEach((p, i) => {
        if (i === 0) ctx.moveTo(p.x, p.y);
        else ctx.lineTo(p.x, p.y);
    });
    ctx.strokeStyle = 'rgba(255,255,255,0.8)';
    ctx.lineWidth = 2;
    ctx.stroke();
}

function drawNodeTypePie(nodeTypes) {
    const canvas = document.getElementById('nodeTypePieCanvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) / 2 - 5;

    ctx.clearRect(0, 0, width, height);

    const total = Object.values(nodeTypes).reduce((a, b) => a + b, 0);
    if (total === 0) return;

    const colors = {
        'process': '#2196F3',
        'file': '#FF9800',
        'socket': '#9C27B0',
        'unknown': '#9E9E9E'
    };

    let startAngle = -Math.PI / 2;

    Object.entries(nodeTypes).forEach(([type, count]) => {
        if (count === 0) return;

        const sliceAngle = (count / total) * Math.PI * 2;
        const endAngle = startAngle + sliceAngle;

        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.arc(centerX, centerY, radius, startAngle, endAngle);
        ctx.closePath();
        ctx.fillStyle = colors[type] || colors.unknown;
        ctx.fill();

        startAngle = endAngle;
    });

    // 中心白圆
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius * 0.5, 0, Math.PI * 2);
    ctx.fillStyle = 'white';
    ctx.fill();
}

// ==================== 窗口大小变化 ====================
window.addEventListener('resize', () => {
    Object.values(overviewCharts).forEach(chart => {
        if (chart && chart.resize) {
            chart.resize();
        }
    });
});

// ==================== 导出 ====================
window.TraceEye = window.TraceEye || {};
window.TraceEye.loadOverviewData = loadOverviewData;
