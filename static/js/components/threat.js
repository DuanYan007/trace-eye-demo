/**
 * 威胁检测页面组件
 */

// 图表实例
let threatTimelineChart = null;
let threatNetworkChart = null;
let threatDistributionChart = null;

// 威胁检测数据缓存
let threatDataCache = null;

// 时间轮当前筛选的威胁等级
let timelineFilterLevel = 'all';

// 时间轮节点数据
let timelineNodesData = [];

const TIMELINE_VISIBLE_LEVELS = ['critical', 'high', 'medium', 'low'];
const NETWORK_VISIBLE_LEVELS = ['critical', 'high', 'medium'];
const THREAT_LEVEL_PRIORITY = { critical: 4, high: 3, medium: 2, low: 1, benign: 0 };

// 节点类型颜色配置（局部变量，避免全局冲突）
const threatNodeTypeColors = {
    'process': '#2196F3',
    'file': '#FF9800',
    'socket': '#9C27B0',
    'unknown': '#9E9E9E'
};

// 威胁等级颜色配置（加前缀避免冲突）
const THREAT_PAGE_LEVEL_COLORS = {
    'critical': '#fb7185',
    'high': '#f59e0b',
    'medium': '#facc15',
    'low': '#34d399',
    'benign': '#94a3b8'
};

// 威胁等级中文名称
const THREAT_LEVEL_NAMES = {
    'critical': '严重',
    'high': '高危',
    'medium': '中危',
    'low': '低危',
    'benign': '正常'
};

// 组件加载完成后的初始化
window.addEventListener('componentLoaded', (e) => {
    if (e.detail.name === 'threat') {
        initThreatPage();
    }
});

/**
 * 初始化威胁检测页面
 */
function initThreatPage() {
    const page = document.getElementById('page-threat');
    if (!page || page.dataset.threatInitialized === 'true') return;
    page.dataset.threatInitialized = 'true';

    const btn = document.getElementById('btnThreat');
    if (btn) {
        btn.addEventListener('click', () => executeStep('threat', '/step/threat'));
    }
}

/**
 * 加载威胁检测页面数据
 * @param {Object} status - 系统状态
 * @param {Object} pageDataCache - 页面缓存数据（仅当步骤完成时有值）
 */
async function loadThreatData(status, pageDataCache) {
    // 检查依赖步骤 rules 是否完成
    if (!status.steps_completed?.rules) {
        // rules 未完成，显示空状态
        return;
    }

    // 隐藏空状态，显示输入数据区域
    document.getElementById('threatInputEmpty').style.display = 'none';
    document.getElementById('threatInputFilled').style.display = 'block';

    // 显示输入数据统计（从系统状态中获取，而不是再次请求缓存）
    try {
        // 使用 status 中的统计数据，或者通过 API 获取
        const stats = status.stats || {};
        const alertsEl = document.getElementById('threatInAlerts');
        if (alertsEl) alertsEl.textContent = stats.total_alerts || '-';

        // 获取图节点数（从 graph 步骤的缓存数据获取）
        const graphData = await DataCache.get('graph');
        const graphInfo = graphData?.data || {};
        const nodesEl = document.getElementById('threatInNodes');
        if (nodesEl) nodesEl.textContent = graphInfo.node_count || graphInfo.summary?.nodes || 0;
    } catch (e) {
        console.error('[Threat] Load input data error:', e);
    }

    // 只有当 threat 步骤完成时，才加载并渲染结果数据
    if (status.steps_completed?.threat) {
        await loadThreatResults(pageDataCache);
    }
}

/**
 * 加载威胁检测结果
 * @param {Object} pageDataCache - 页面缓存数据
 */
async function loadThreatResults(pageDataCache) {
    try {
        // 使用缓存数据
        const threatCache = pageDataCache || await DataCache.get('threat');
        const data = threatCache?.data || {};
        threatDataCache = data;

        console.log('[Threat] Loaded data from cache');

        const summary = threatDataCache.summary || {};
        const classifiedNodes = threatDataCache.classified_nodes || {};
        const threatScores = threatDataCache.threat_scores || {};
        const nodeFeatures = threatDataCache.node_features || {};

        // 更新威胁等级卡片
        updateThreatOverviewCards(summary);

        // 渲染威胁时间线
        await renderThreatTimeline(classifiedNodes, nodeFeatures);

        // 渲染节点关系网络
        await renderThreatNetwork(classifiedNodes, threatScores);

        // 渲染异常分数分布
        renderThreatDistribution(threatScores);

        // 显示下载按钮
        const downloadBtn = document.getElementById('downloadThreat');
        if (downloadBtn) {
            downloadBtn.style.display = 'inline-block';
        }

        // 显示输出区域
        document.getElementById('threatOutputSection').style.display = 'block';

    } catch (e) {
        console.error('[Threat] Load results error:', e);
    }
}

/**
 * 更新威胁等级总览卡片
 */
function updateThreatOverviewCards(summary) {
    const byLevel = summary.by_level || {};

    const setSafe = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    };

    setSafe('threatCriticalCount', byLevel.critical || 0);
    setSafe('threatHighCount', byLevel.high || 0);
    setSafe('threatMediumCount', byLevel.medium || 0);
    setSafe('threatLowCount', byLevel.low || 0);
    setSafe('threatBenignCount', byLevel.benign || 0);
}

/**
 * 渲染威胁时间线 - 环形时间轮
 */
async function renderThreatTimeline(classifiedNodes, nodeFeatures) {
    const container = document.getElementById('threatTimelineChart');
    if (!container) return;

    // 如果容器宽度为0，延迟渲染
    if (container.clientWidth === 0) {
        console.log('[Threat] Container width is 0, delaying render...');
        setTimeout(() => renderThreatTimeline(classifiedNodes, nodeFeatures), 100);
        return;
    }

    // 初始化图表
    if (threatTimelineChart) {
        threatTimelineChart.dispose();
    }
    threatTimelineChart = echarts.init(container);

    // 时间轮只展示异常/威胁侧节点，避免把全部正常节点塞进环形图。
    const allNodes = [];
    const scoreMap = threatDataCache.threat_scores || threatDataCache.anomaly_detection?.scores || {};

    for (const level of TIMELINE_VISIBLE_LEVELS) {
        const nodes = classifiedNodes[level] || [];
        nodes.forEach(nodeId => {
            const score = Number(scoreMap[nodeId] || 0);
            allNodes.push({
                id: nodeId,
                level: level,
                score: score
            });
        });
    }

    allNodes.sort((a, b) =>
        (THREAT_LEVEL_PRIORITY[b.level] - THREAT_LEVEL_PRIORITY[a.level]) ||
        (b.score - a.score)
    );

    // 获取图数据来获取节点信息
    let graphData = null;
    try {
        const graphCache = await DataCache.get('graph');
        graphData = graphCache?.data || graphCache || {};
    } catch (e) {
        console.error('[Threat] Failed to load graph data:', e);
    }

    const nodesMap = {};
    if (graphData?.nodes) {
        graphData.nodes.forEach(node => {
            nodesMap[node.id] = node;
        });
    }

    // 保存节点数据用于筛选
    timelineNodesData = allNodes.map(node => ({
        ...node,
        name: nodesMap[node.id]?.name || node.id,
        type: nodesMap[node.id]?.type || 'unknown'
    }));

    // 更新统计
    const criticalCount = (classifiedNodes.critical || []).length;
    const highCount = (classifiedNodes.high || []).length;
    const highRiskCountEl = document.getElementById('timelineHighRiskCount');
    if (highRiskCountEl) highRiskCountEl.textContent = criticalCount + highCount;

    // 渲染环形图
    renderTimelineWheel(timelineNodesData, nodesMap);
}

/**
 * 渲染环形时间轮
 */
function renderTimelineWheel(nodes, nodesMap) {
    // 按威胁等级分组统计
    const levelCounts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        benign: 0
    };

    nodes.forEach(node => {
        if (levelCounts.hasOwnProperty(node.level)) {
            levelCounts[node.level]++;
        }
    });

    // 根据当前筛选过滤数据
    // 构建环形图数据
    const pieData = [
        { name: '严重', value: levelCounts.critical, level: 'critical', itemStyle: { color: THREAT_PAGE_LEVEL_COLORS.critical } },
        { name: '高危', value: levelCounts.high, level: 'high', itemStyle: { color: THREAT_PAGE_LEVEL_COLORS.high } },
        { name: '中危', value: levelCounts.medium, level: 'medium', itemStyle: { color: THREAT_PAGE_LEVEL_COLORS.medium } },
        { name: '低危', value: levelCounts.low, level: 'low', itemStyle: { color: THREAT_PAGE_LEVEL_COLORS.low } }
    ].filter(d => d.value > 0);

    // 更新中心信息
    updateCenterInfo();

    const option = {
        backgroundColor: 'transparent',
        tooltip: {
            trigger: 'item',
            formatter: '{b}: {c} 个节点 ({d}%)',
            backgroundColor: 'rgba(8, 18, 38, 0.96)',
            borderColor: 'rgba(125, 178, 255, 0.28)',
            textStyle: { color: '#dbeafe' }
        },
        legend: {
            show: false
        },
        series: [{
            type: 'pie',
            radius: ['40%', '65%'],
            center: ['50%', '50%'],
            data: pieData,
            itemStyle: {
                borderRadius: 8,
                borderColor: 'rgba(7, 17, 31, 0.96)',
                borderWidth: 2
            },
            label: {
                show: true,
                formatter: '{b}\n{c}',
                fontSize: 13,
                fontWeight: 600,
                color: '#dbeafe',
                textBorderColor: 'rgba(3, 10, 24, 0.92)',
                textBorderWidth: 3
            },
            labelLine: {
                length: 15,
                length2: 10
            },
            emphasis: {
                scale: true,
                scaleSize: 10,
                itemStyle: {
                    shadowBlur: 15,
                    shadowOffsetX: 0,
                    shadowColor: 'rgba(0, 0, 0, 0.3)'
                }
            }
        }]
    };

    threatTimelineChart.setOption(option);

    // 绑定点击事件
    threatTimelineChart.off('click');
    threatTimelineChart.on('click', function(params) {
        if (params.data) {
            filterTimelineByLevel(params.data.level);
        }
    });

    // 更新节点列表
    updateNodesList();

    // 窗口调整
    window.addEventListener('resize', () => threatTimelineChart && threatTimelineChart.resize());
}

/**
 * 按威胁等级筛选时间轮
 */
function filterTimelineByLevel(level) {
    timelineFilterLevel = level;

    // 更新按钮状态
    const filterBtns = document.querySelectorAll('.timeline-filter-btn');
    filterBtns.forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.level === level) {
            btn.classList.add('active');
        }
    });

    // 更新筛选显示
    const levelNames = {
        'all': '全部',
        'critical': '严重',
        'high': '高危',
        'medium': '中危',
        'low': '低危'
    };
    const currentFilterEl = document.getElementById('timelineCurrentFilter');
    if (currentFilterEl) currentFilterEl.textContent = levelNames[level] || '全部';

    // 重新渲染图表
    renderTimelineWheel(timelineNodesData, {});

    // 更新中心信息
    updateCenterInfo();

    // 更新节点列表
    updateNodesList();
}

/**
 * 更新中心信息显示
 */
function updateCenterInfo() {
    const levelNames = {
        'all': '全部',
        'critical': '严重',
        'high': '高危',
        'medium': '中危',
        'low': '低危'
    };

    const filteredNodes = timelineFilterLevel === 'all'
        ? timelineNodesData
        : timelineNodesData.filter(n => n.level === timelineFilterLevel);

    const centerInfoLevelEl = document.getElementById('centerInfoLevel');
    const centerInfoCountEl = document.getElementById('centerInfoCount');
    if (centerInfoLevelEl) centerInfoLevelEl.textContent = levelNames[timelineFilterLevel] || '全部';
    if (centerInfoCountEl) centerInfoCountEl.textContent = filteredNodes.length;
}

/**
 * 更新节点列表
 */
function updateNodesList() {
    const container = document.getElementById('timelineNodesList');
    if (!container) return;

    const filteredAll = timelineFilterLevel === 'all'
        ? timelineNodesData
        : timelineNodesData.filter(n => n.level === timelineFilterLevel);
    const filteredNodes = filteredAll.slice(0, 20); // 最多显示20个

    if (filteredNodes.length === 0) {
        container.innerHTML = '<p style="text-align:center; color:#999; padding:15px;">暂无节点</p>';
        return;
    }

    container.innerHTML = filteredNodes.map(node => {
        const levelClass = node.level;
        const scorePercent = (node.score * 100).toFixed(1);
        return `
            <div class="timeline-node-item" onclick="showNodeDetail('${node.id}')">
                <span class="node-item-dot ${levelClass}"></span>
                <span class="node-item-name">${escapeHtml(node.name)}</span>
                <span class="node-item-score">${scorePercent}%</span>
                <span class="node-item-level ${levelClass}">${THREAT_LEVEL_NAMES[node.level]}</span>
            </div>
        `;
    }).join('');

    if (filteredAll.length > 20) {
        container.innerHTML += `<p style="text-align:center; color:#a8b8d2; font-size:0.85rem; padding:10px;">...还有 ${filteredAll.length - 20} 个节点</p>`;
    }
}

/**
 * 显示节点详情
 */
function showNodeDetail(nodeId) {
    const node = timelineNodesData.find(n => n.id === nodeId);
    if (!node) return;

    const typeLabels = { 'process': '进程', 'file': '文件', 'socket': '网络', 'unknown': '未知' };

    // 使用 alert 显示详情（简单实现）
    alert(`节点详情\n\n名称: ${node.name}\n类型: ${typeLabels[node.type] || node.type}\n威胁等级: ${THREAT_LEVEL_NAMES[node.level]}\n威胁评分: ${(node.score * 100).toFixed(2)}%`);
}

/**
 * 获取威胁等级优先级（用于Y轴排序）
 */
function getLevelPriority(level) {
    const priorities = { 'critical': 3, 'high': 2, 'medium': 1, 'low': 0, 'benign': -1 };
    return priorities[level] ?? 0;
}

/**
 * 显示时间线详情面板
 */
function showTimelineDetail(node, nodesMap) {
    const panel = document.getElementById('timelineDetailPanel');
    const content = document.getElementById('timelineDetailContent');

    if (!panel || !content) return;

    const nodeInfo = nodesMap[node.id] || {};
    const typeLabels = { 'process': '进程', 'file': '文件', 'socket': '网络', 'unknown': '未知' };

    content.innerHTML = `
        <div class="detail-section">
            <div class="detail-section-title">节点信息</div>
            <div class="detail-item">
                <span class="detail-item-label">节点名称</span>
                <span class="detail-item-value">${escapeHtml(nodeInfo.name || node.id)}</span>
            </div>
            <div class="detail-item">
                <span class="detail-item-label">节点类型</span>
                <span class="detail-item-value">${typeLabels[nodeInfo.type] || nodeInfo.type || '未知'}</span>
            </div>
            <div class="detail-item">
                <span class="detail-item-label">威胁等级</span>
                <span class="detail-item-value">
                    <span class="detail-badge ${node.level}">${THREAT_LEVEL_NAMES[node.level]}</span>
                </span>
            </div>
            <div class="detail-item">
                <span class="detail-item-label">威胁评分</span>
                <span class="detail-item-value">${(node.score * 100).toFixed(2)}%</span>
            </div>
        </div>
    `;

    panel.style.display = 'block';
}

/**
 * 关闭时间线详情面板
 */
function closeTimelineDetailPanel() {
    const panel = document.getElementById('timelineDetailPanel');
    if (panel) {
        panel.style.display = 'none';
    }
}

/**
 * 渲染节点关系网络
 */
async function renderThreatNetwork(classifiedNodes, threatScores) {
    const container = document.getElementById('threatNetworkChart');
    if (!container) return;

    // 如果容器宽度为0，延迟渲染
    if (container.clientWidth === 0) {
        console.log('[Threat] Network container width is 0, delaying render...');
        setTimeout(() => renderThreatNetwork(classifiedNodes, threatScores), 100);
        return;
    }

    // 初始化图表
    if (threatNetworkChart) {
        threatNetworkChart.dispose();
    }
    threatNetworkChart = echarts.init(container);

    // 获取图数据
    let graphData = null;
    try {
        const graphCache = await DataCache.get('graph');
        graphData = graphCache?.data || graphCache || {};
    } catch (e) {
        console.error('[Threat] Failed to load graph data for network:', e);
        return;
    }

    if (!graphData || !graphData.nodes || !graphData.edges) {
        container.innerHTML = '<p style="text-align:center; padding:50px; color:#999;">暂无图数据</p>';
        return;
    }

    const nodeLevelMap = {};
    NETWORK_VISIBLE_LEVELS.forEach(level => {
        (classifiedNodes[level] || []).forEach(nodeId => {
            nodeLevelMap[nodeId] = level;
        });
    });

    const degreeMap = {};
    (graphData.edges || []).forEach(edge => {
        degreeMap[edge.source] = (degreeMap[edge.source] || 0) + 1;
        degreeMap[edge.target] = (degreeMap[edge.target] || 0) + 1;
    });

    const nodesById = {};
    graphData.nodes.forEach(node => {
        nodesById[node.id] = node;
    });

    const candidateIds = Object.keys(nodeLevelMap)
        .filter(nodeId => nodesById[nodeId])
        .sort((a, b) =>
            (THREAT_LEVEL_PRIORITY[nodeLevelMap[b]] - THREAT_LEVEL_PRIORITY[nodeLevelMap[a]]) ||
            ((threatScores[b] || 0) - (threatScores[a] || 0)) ||
            ((degreeMap[b] || 0) - (degreeMap[a] || 0))
        );

    const candidateSet = new Set(candidateIds.slice(0, 350));
    const connectedIds = new Set();
    const candidateEdges = graphData.edges.filter(edge => {
        const keep = candidateSet.has(edge.source) && candidateSet.has(edge.target);
        if (keep) {
            connectedIds.add(edge.source);
            connectedIds.add(edge.target);
        }
        return keep;
    });

    const MAX_NODES = 80;
    const selectedIds = (connectedIds.size > 0
        ? candidateIds.filter(id => connectedIds.has(id))
        : candidateIds
    ).slice(0, MAX_NODES);

    const nodeSet = new Set(selectedIds);
    const displayNodes = selectedIds.map(id => nodesById[id]).filter(Boolean);

    const nodes = displayNodes.map(node => {
        const threatScore = threatScores[node.id] || 0;
        const level = nodeLevelMap[node.id] || 'medium';

        const nodeType = node.type || 'unknown';
        const baseColor = threatNodeTypeColors[nodeType] || threatNodeTypeColors.unknown;

        return {
            id: node.id,
            name: node.name || node.id,
            value: node.degree || 0,
            itemType: nodeType,
            threatLevel: level,
            threatScore: threatScore,
            itemStyle: {
                color: level === 'critical' ? THREAT_PAGE_LEVEL_COLORS.critical :
                       level === 'high' ? THREAT_PAGE_LEVEL_COLORS.high :
                       level === 'medium' ? THREAT_PAGE_LEVEL_COLORS.medium : baseColor,
                borderColor: level === 'critical' ? '#c0392b' :
                            level === 'high' ? '#f59e0b' :
                            level === 'medium' ? '#facc15' :
                            'rgba(219, 234, 254, 0.76)',
                borderWidth: level === 'critical' ? 3 : level === 'high' ? 2 : 1
            },
            symbolSize: Math.min(34, 15 + (degreeMap[node.id] || node.degree || 0) * 0.45),
            symbol: nodeType === 'process' ? 'circle' : nodeType === 'file' ? 'rect' : 'diamond',
            label: {
                show: (degreeMap[node.id] || node.degree || 0) > 2,
                formatter: function(params) {
                    const name = params.data.name;
                    return name.length > 12 ? name.substring(0, 10) + '...' : name;
                },
                fontSize: 10,
                color: '#dbeafe',
                textBorderColor: 'rgba(3, 10, 24, 0.88)',
                textBorderWidth: 3
            }
        };
    });

    // 过滤边：只显示两个端点都在显示节点集合中的边
    const displayEdges = candidateEdges
        .filter(e => nodeSet.has(e.source) && nodeSet.has(e.target))
        .slice(0, 200);

    if (displayNodes.length === 0) {
        container.innerHTML = '<p style="text-align:center; padding:50px; color:#a8b8d2;">暂无可展示的高风险关联节点</p>';
        return;
    }

    const links = displayEdges.map(edge => ({
        source: edge.source,
        target: edge.target,
        lineStyle: {
            color: 'rgba(148, 163, 184, 0.42)',
            width: Math.min((edge.weight || 1) * 0.5, 2),
            opacity: 0.5
        }
    }));

    const option = {
        backgroundColor: 'transparent',
        tooltip: {
            backgroundColor: 'rgba(8, 18, 38, 0.96)',
            borderColor: 'rgba(125, 178, 255, 0.28)',
            textStyle: { color: '#dbeafe' },
            formatter: function(params) {
                if (params.dataType === 'node') {
                    const typeLabels = { 'process': '进程', 'file': '文件', 'socket': '网络', 'unknown': '未知' };
                    return `
                        <div style="padding:8px;">
                            <strong>${params.data.name}</strong><br/>
                            <span style="color:#cbd5e1;">类型: ${typeLabels[params.data.itemType] || '未知'}</span><br/>
                            <span style="color:#cbd5e1;">威胁等级: ${THREAT_LEVEL_NAMES[params.data.threatLevel] || '未知'}</span><br/>
                            <span style="color:#cbd5e1;">威胁评分: ${(params.data.threatScore * 100).toFixed(1)}%</span>
                        </div>
                    `;
                }
                return params.name;
            }
        },
        series: [{
            type: 'graph',
            layout: 'force',
            data: nodes,
            links: links,
            roam: true,
            draggable: true,
            focusNodeAdjacency: true,
            emphasis: {
                focus: 'adjacency',
                lineStyle: {
                    width: 3
                },
                itemStyle: {
                    borderWidth: 3
                }
            },
            force: {
                repulsion: 200,
                edgeLength: [30, 100],
                gravity: 0.1
            },
            lineStyle: {
                color: 'source',
                curveness: 0.1
            }
        }]
    };

    threatNetworkChart.setOption(option);

    // 窗口调整
    window.addEventListener('resize', () => threatNetworkChart && threatNetworkChart.resize());
}

/**
 * 重置网络图缩放
 */
function resetNetworkZoom() {
    if (threatNetworkChart) {
        threatNetworkChart.dispatchAction({
            type: 'restore'
        });
    }
}

/**
 * 渲染异常分数分布直方图
 */
function renderThreatDistribution(threatScores) {
    const container = document.getElementById('threatDistributionChart');
    if (!container) return;

    // 如果容器宽度为0，延迟渲染
    if (container.clientWidth === 0) {
        console.log('[Threat] Distribution container width is 0, delaying render...');
        setTimeout(() => renderThreatDistribution(threatScores), 100);
        return;
    }

    const rawScores = Object.values(threatScores || {});
    const fallbackScores = Object.values(threatDataCache?.anomaly_detection?.scores || {});
    const scores = (rawScores.length > 0 ? rawScores : fallbackScores)
        .map(score => Number(score))
        .filter(score => Number.isFinite(score));

    if (scores.length === 0) {
        if (threatDistributionChart) {
            threatDistributionChart.dispose();
            threatDistributionChart = null;
        }
        container.innerHTML = '<p style="text-align:center; padding:50px; color:#a8b8d2;">暂无异常分数数据，请重新执行威胁检测</p>';
        return;
    }

    container.innerHTML = '';

    // 初始化图表
    if (threatDistributionChart) {
        threatDistributionChart.dispose();
    }
    threatDistributionChart = echarts.init(container);

    // 构建分数分布数据
    const bins = [0, 0, 0, 0, 0]; // 0-0.2, 0.2-0.4, 0.4-0.6, 0.6-0.8, 0.8-1.0

    scores.forEach(score => {
        if (score < 0.2) bins[0]++;
        else if (score < 0.4) bins[1]++;
        else if (score < 0.6) bins[2]++;
        else if (score < 0.8) bins[3]++;
        else bins[4]++;
    });

    const option = {
        backgroundColor: 'transparent',
        grid: {
            left: '10%',
            right: '5%',
            top: '15%',
            bottom: '15%'
        },
        title: {
            text: '异常分数分布',
            left: 'center',
            textStyle: {
                fontSize: 14,
                color: '#dbeafe'
            }
        },
        tooltip: {
            formatter: '{b}: {c} 个节点',
            backgroundColor: 'rgba(8, 18, 38, 0.96)',
            borderColor: 'rgba(125, 178, 255, 0.28)',
            textStyle: { color: '#dbeafe' }
        },
        xAxis: {
            type: 'category',
            data: ['正常\n0-0.2', '低危\n0.2-0.4', '中危\n0.4-0.6', '高危\n0.6-0.8', '严重\n0.8-1.0'],
            axisLabel: {
                fontSize: 11,
                color: '#cbd5e1'
            }
        },
        yAxis: {
            type: 'value',
            name: '节点数量',
            nameTextStyle: { color: '#cbd5e1' },
            axisLabel: {
                color: '#cbd5e1'
            },
            splitLine: {
                lineStyle: { color: 'rgba(148, 163, 184, 0.12)' }
            }
        },
        series: [{
            type: 'bar',
            data: bins.map((count, index) => ({
                value: count,
                itemStyle: {
                    color: [
                        THREAT_PAGE_LEVEL_COLORS.benign,
                        THREAT_PAGE_LEVEL_COLORS.low,
                        THREAT_PAGE_LEVEL_COLORS.medium,
                        THREAT_PAGE_LEVEL_COLORS.high,
                        THREAT_PAGE_LEVEL_COLORS.critical
                    ][index]
                }
            })),
            barWidth: '60%',
            label: {
                show: true,
                position: 'top',
                color: '#dbeafe'
            }
        }]
    };

    threatDistributionChart.setOption(option);

    // 窗口调整
    window.addEventListener('resize', () => threatDistributionChart && threatDistributionChart.resize());
}

/**
 * 执行处理步骤
 */
async function executeStep(pageId, apiEndpoint) {
    return runStepWithLock(pageId, apiEndpoint);
}

/**
 * 轮询任务状态（Debug 模式使用，暂未启用）
 */
async function pollTaskStatus(pageId, apiEndpoint) {
    await apiPost(apiEndpoint.replace('/api/step/', '/api/start/'));

    const pollInterval = setInterval(async () => {
        try {
            const status = await apiGet(`/status/step/${pageId}`);

            if (status.error) {
                clearInterval(pollInterval);
                hideProcessSection(pageId);
                alert(`处理失败: ${status.error}`);
                return;
            }

            const progress = status.progress || 0;
            updateProgress(pageId, progress, status.message || '处理中...');
            updateStepDots(pageId, status.current_step);

            if (status.completed) {
                clearInterval(pollInterval);
                updateProgress(pageId, 100, '完成');

                setTimeout(async () => {
                    hideProcessSection(pageId);
                    DataCache.clear(pageId);
                    await loadPageData(pageId);
                }, 500);
            }
        } catch (error) {
            clearInterval(pollInterval);
            hideProcessSection(pageId);
            console.error('轮询状态失败:', error);
        }
    }, 500);
}

/**
 * 更新步骤点状态
 */
function updateStepDots(pageId, currentStep) {
    const container = document.getElementById(`${pageId}ProcessSection`);
    if (!container) return;

    const stepDots = container.querySelectorAll('.process-step');
    stepDots.forEach((dot, index) => {
        const stepNum = parseInt(dot.dataset.step);
        const dotSpan = dot.querySelector('.step-dot');

        if (stepNum < currentStep) {
            dotSpan.textContent = '✓';
            dotSpan.style.color = 'var(--success-color)';
        } else if (stepNum === currentStep) {
            dotSpan.textContent = '◉';
            dotSpan.style.color = 'var(--primary-color)';
        }
    });
}

/**
 * 显示处理进度区域
 */
function showProcessSection(page) {
    const section = document.getElementById(`${page}ProcessSection`);
    if (section) {
        section.style.display = 'block';
    }
}

/**
 * 隐藏处理进度区域
 */
function hideProcessSection(page) {
    const section = document.getElementById(`${page}ProcessSection`);
    if (section) {
        section.style.display = 'none';
    }
}

/**
 * 更新进度
 */
function updateProgress(page, percent, message) {
    const fill = document.getElementById(`${page}ProcessFill`);
    const text = document.getElementById(`${page}ProcessText`);
    const msg = document.getElementById(`${page}ProcessMessage`);

    if (fill) fill.style.width = `${percent}%`;
    if (text) text.textContent = `${percent}%`;
    if (msg) msg.textContent = message;
}

/**
 * HTML转义
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// 覆盖main.js中的占位函数
window.TraceEye = window.TraceEye || {};
window.TraceEye.loadThreatData = loadThreatData;
window.resetNetworkZoom = resetNetworkZoom;
window.filterTimelineByLevel = filterTimelineByLevel;
window.showNodeDetail = showNodeDetail;
window.executeStep = executeStep;
