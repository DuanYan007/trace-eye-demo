/**
 * 关系挖掘页面组件
 * 威胁节点列表 + 辐射关系网络
 */

// 图表实例
let relationsChart = null;
let showLabels = true;

// 关系挖掘数据缓存
let relationsDataCache = null;

// 当前选中的威胁节点
let selectedThreatNode = null;

// 威胁节点列表数据
let threatNodesList = [];
let totalThreatNodeCount = 0;
let relatedThreatNodeCount = 0;

const RELATIONS_NODE_DISPLAY_LIMIT = 80;
const RELATIONS_LEVEL_PRIORITY = { critical: 4, high: 3, medium: 2, low: 1, benign: 0 };

// 组件加载完成后的初始化
window.addEventListener('componentLoaded', (e) => {
    if (e.detail.name === 'relations') {
        initRelationsPage();
    }
});

/**
 * 初始化关系挖掘页面
 */
function initRelationsPage() {
    const page = document.getElementById('page-relations');
    if (!page || page.dataset.relationsInitialized === 'true') return;
    page.dataset.relationsInitialized = 'true';

    const btn = document.getElementById('btnRelations');
    if (btn) {
        btn.addEventListener('click', () => executeStep('relations', '/step/relations'));
    }
}

/**
 * 加载关系挖掘页面数据
 */
async function loadRelationsData(status, pageDataCache) {
    console.log('[Relations] loadRelationsData called', {
        threatCompleted: status.steps_completed?.threat,
        relationsCompleted: status.steps_completed?.relations
    });

    if (status.steps_completed?.threat) {
        document.getElementById('relationsInputEmpty').style.display = 'none';
        document.getElementById('relationsInputFilled').style.display = 'block';

        try {
            const threatData = await DataCache.get('threat');
            const data = threatData?.data || threatData || {};
            const summary = threatData?.summary || {};

            const anomaliesEl = document.getElementById('relationsInAnomalies');
            if (anomaliesEl) anomaliesEl.textContent = data.anomaly_count || summary.anomaly_count || 0;

            const graphData = await DataCache.get('graph');
            const graphInfo = graphData?.data || graphData || {};
            const graphSummary = graphData?.summary || {};
            const nodesEl = document.getElementById('relationsInNodes');
            if (nodesEl) nodesEl.textContent = graphInfo.node_count || graphSummary.nodes || 0;

            console.log('[Relations] Input data loaded', {
                anomalies: data.anomaly_count || summary.anomaly_count,
                nodes: graphInfo.node_count || graphSummary.nodes
            });
        } catch (e) {
            console.error('[Relations] Load input data error:', e);
        }

        if (status.steps_completed?.relations) {
            console.log('[Relations] Loading results...');
            await loadRelationsResults(pageDataCache);
        } else {
            console.log('[Relations] Relations step not completed, skipping results');
        }
    } else {
        console.log('[Relations] Threat step not completed');
    }
}

/**
 * 加载关系挖掘结果
 */
async function loadRelationsResults(pageDataCache) {
    try {
        // 使用缓存数据
        const relationsCache = pageDataCache || await DataCache.get('relations');
        const data = relationsCache?.data || relationsCache || {};
        relationsDataCache = data;

        console.log('[Relations] Loaded data from cache');

        const statistics = relationsDataCache.statistics || {};
        const suspiciousRelations = relationsDataCache.suspicious_relations || [];
        const suspiciousSubgraphs = relationsDataCache.suspicious_subgraphs || [];

        // 更新统计
        document.getElementById('relationsOutTotal').textContent = statistics.total_relations || suspiciousRelations.length || 0;
        document.getElementById('relationsOutCorrelation').textContent = (statistics.avg_correlation || 0).toFixed(3);
        document.getElementById('relationsOutSubgraphs').textContent = statistics.total_subgraphs || suspiciousSubgraphs.length || 0;

        // 获取威胁节点数据
        await loadThreatNodes();

        // 显示下载按钮
        const downloadBtn = document.getElementById('downloadRelations');
        if (downloadBtn) {
            downloadBtn.style.display = 'inline-block';
        }

        // 显示输出区域
        document.getElementById('relationsOutputSection').style.display = 'block';

    } catch (e) {
        console.error('[Relations] Load results error:', e);
    }
}

/**
 * 加载威胁节点列表
 */
async function loadThreatNodes() {
    try {
        // 获取威胁检测数据
        const threatCache = await DataCache.get('threat');
        const threatData = threatCache?.data || threatCache || {};
        const classifiedNodes = threatData.classified_nodes || {};
        const threatScores = threatData.threat_scores || {};

        // 获取图数据以获取节点信息
        const graphCache = await DataCache.get('graph');
        const graphData = graphCache?.data || graphCache || {};
        const nodesMap = {};
        if (graphData.nodes) {
            graphData.nodes.forEach(node => {
                nodesMap[node.id] = node;
            });
        }

        const suspiciousRelations = relationsDataCache?.suspicious_relations || [];
        const relationStats = {};
        suspiciousRelations.forEach(rel => {
            [rel.source, rel.target].forEach(nodeId => {
                if (!nodeId) return;
                relationStats[nodeId] = relationStats[nodeId] || { count: 0, maxCorrelation: 0 };
                relationStats[nodeId].count += 1;
                relationStats[nodeId].maxCorrelation = Math.max(
                    relationStats[nodeId].maxCorrelation,
                    Number(rel.correlation || 0)
                );
            });
        });

        // 收集威胁节点（critical + high + medium），优先展示已进入可疑关系的节点。
        const threatLevels = ['critical', 'high', 'medium'];
        threatNodesList = [];

        for (const level of threatLevels) {
            const nodes = classifiedNodes[level] || [];
            nodes.forEach(nodeId => {
                const nodeInfo = nodesMap[nodeId] || {};
                const score = threatScores[nodeId] || 0;

                threatNodesList.push({
                    id: nodeId,
                    name: nodeInfo.name || nodeId,
                    type: nodeInfo.type || 'unknown',
                    level: level,
                    score: score,
                    degree: nodeInfo.degree || 0,
                    relationCount: relationStats[nodeId]?.count || 0,
                    maxCorrelation: relationStats[nodeId]?.maxCorrelation || 0
                });
            });
        }

        totalThreatNodeCount = threatNodesList.length;
        relatedThreatNodeCount = threatNodesList.filter(node => node.relationCount > 0).length;

        // 按可疑关系、等级、威胁评分排序；避免大量孤立节点把列表撑爆。
        threatNodesList.sort((a, b) =>
            (b.relationCount - a.relationCount) ||
            (b.maxCorrelation - a.maxCorrelation) ||
            (RELATIONS_LEVEL_PRIORITY[b.level] - RELATIONS_LEVEL_PRIORITY[a.level]) ||
            (b.score - a.score) ||
            (b.degree - a.degree)
        );

        const relatedNodes = threatNodesList.filter(node => node.relationCount > 0);
        const isolatedNodes = threatNodesList.filter(node => node.relationCount === 0);
        threatNodesList = relatedNodes.length > 0
            ? relatedNodes.slice(0, RELATIONS_NODE_DISPLAY_LIMIT)
            : isolatedNodes.slice(0, RELATIONS_NODE_DISPLAY_LIMIT);

        // 渲染威胁节点列表
        renderThreatNodesList();

        if (threatNodesList.length > 0) {
            await selectThreatNode(threatNodesList[0].id);
        }

    } catch (e) {
        console.error('[Relations] Load threat nodes error:', e);
    }
}

/**
 * 渲染威胁节点列表
 */
function renderThreatNodesList() {
    const container = document.getElementById('threatNodesList');
    if (!container) return;

    if (threatNodesList.length === 0) {
        container.innerHTML = '<p style="text-align:center; color:#999; padding:20px;">暂无威胁节点</p>';
        document.getElementById('relationsOutThreatNodes').textContent = '0';
        return;
    }

    const outThreatNodes = document.getElementById('relationsOutThreatNodes');
    if (outThreatNodes) {
        outThreatNodes.textContent = relatedThreatNodeCount > 0
            ? `${threatNodesList.length}/${relatedThreatNodeCount}`
            : `${threatNodesList.length}/${totalThreatNodeCount}`;
        outThreatNodes.title = relatedThreatNodeCount > 0
            ? `当前展示 ${threatNodesList.length} 个有可疑关系的威胁节点，共 ${relatedThreatNodeCount} 个`
            : `当前展示 ${threatNodesList.length} 个威胁节点，共 ${totalThreatNodeCount} 个`;
    }

    container.innerHTML = threatNodesList.map((node, index) => {
        const levelClass = node.level;
        const scorePercent = (node.score * 100).toFixed(1);
        const isSelected = selectedThreatNode && selectedThreatNode.id === node.id;
        const escapedId = escapeJsString(node.id);

        return `
            <div class="threat-node-card ${isSelected ? 'selected' : ''}" onclick="selectThreatNode('${escapedId}')">
                <div class="node-card-header">
                    <span class="node-card-rank">#${index + 1}</span>
                    <span class="node-card-level ${levelClass}">${getThreatLevelName(node.level)}</span>
                </div>
                <div class="node-card-name">${escapeHtml(node.name)}</div>
                <div class="node-card-stats">
                    <span class="node-stat">评分: <strong>${scorePercent}%</strong></span>
                    <span class="node-stat">关系: ${node.relationCount}</span>
                </div>
                <div class="node-card-footer">
                    <span class="node-card-type">${getTypeLabel(node.type)}</span>
                    <span class="node-stat">度数: ${node.degree}</span>
                </div>
            </div>
        `;
    }).join('');
}

/**
 * 选择威胁节点并显示其辐射关系
 */
async function selectThreatNode(nodeId) {
    const node = threatNodesList.find(n => n.id === nodeId);
    if (!node) return;

    selectedThreatNode = node;

    // 更新选中状态
    renderThreatNodesList();

    // 更新网络标题
    document.getElementById('networkTitle').textContent = `🕸️ ${node.name} 的辐射关系`;

    // 显示选中节点信息
    const infoPanel = document.getElementById('selectedNodeInfo');
    infoPanel.style.display = 'block';
    document.getElementById('selectedNodeName').textContent = node.name;
    document.getElementById('selectedNodeLevel').textContent = getThreatLevelName(node.level);
    document.getElementById('selectedNodeLevel').className = `node-info-level ${node.level}`;

    // 隐藏占位符，显示图表
    document.getElementById('networkPlaceholder').style.display = 'none';
    document.getElementById('radiationNetworkChart').style.display = 'block';

    // 渲染辐射关系网络
    await renderRadiationNetwork(nodeId);

    // 更新关系详情表格
    await updateRelationsTable(nodeId);
}

/**
 * 渲染辐射关系网络图
 */
async function renderRadiationNetwork(centerNodeId) {
    const container = document.getElementById('radiationNetworkChart');
    if (!container) return;

    // 如果容器宽度为0，延迟渲染
    if (container.clientWidth === 0) {
        setTimeout(() => renderRadiationNetwork(centerNodeId), 100);
        return;
    }

    // 初始化图表
    if (relationsChart) {
        relationsChart.dispose();
    }
    relationsChart = echarts.init(container);

    // 获取该威胁节点的辐射关系
    const suspiciousRelations = relationsDataCache.suspicious_relations || [];
    const nodeRelations = suspiciousRelations.filter(rel =>
        rel.source === centerNodeId || rel.target === centerNodeId
    );

    // 更新统计信息
    document.getElementById('selectedNodeRelations').textContent = nodeRelations.length;
    const avgCorr = nodeRelations.length > 0
        ? nodeRelations.reduce((sum, r) => sum + (r.correlation || 0), 0) / nodeRelations.length
        : 0;
    document.getElementById('selectedNodeCorrelation').textContent = avgCorr.toFixed(3);

    if (nodeRelations.length === 0) {
        if (relationsChart) {
            relationsChart.dispose();
            relationsChart = null;
        }
        container.style.display = 'none';
        const placeholder = document.getElementById('networkPlaceholder');
        if (placeholder) {
            placeholder.style.display = 'flex';
            placeholder.innerHTML = `
                <div class="placeholder-icon">⛓</div>
                <p>该节点暂未发现可疑关系</p>
                <p>左侧列表已优先展示有关系的节点，可重新执行关系挖掘刷新结果</p>
            `;
        }
        return;
    }

    // 获取图数据
    const graphCache = await DataCache.get('graph');
    const graphData = graphCache?.data || graphCache || {};
    const nodesMap = {};
    if (graphData.nodes) {
        graphData.nodes.forEach(node => {
            nodesMap[node.id] = node;
        });
    }

    // 收集相关节点
    const relatedNodeIds = new Set([centerNodeId]);
    nodeRelations.forEach(rel => {
        relatedNodeIds.add(rel.source);
        relatedNodeIds.add(rel.target);
    });

    // 构建节点数据
    const nodes = [];
    const links = [];

    // 中心节点（威胁节点）
    const centerNode = nodesMap[centerNodeId] || { name: centerNodeId, type: 'unknown' };
    nodes.push({
        id: centerNodeId,
        name: centerNode.name || centerNodeId,
        value: 100,
        category: 'threat',
        itemStyle: {
            color: RELATIONS_LEVEL_COLORS[selectedThreatNode?.level] || RELATIONS_LEVEL_COLORS.critical,
            borderColor: 'rgba(219, 234, 254, 0.82)',
            borderWidth: 3
        },
        symbolSize: 40,
        label: {
            show: true,
            fontSize: 14,
            fontWeight: 'bold',
            color: '#dbeafe',
            textBorderColor: 'rgba(3, 10, 24, 0.88)',
            textBorderWidth: 3
        }
    });

    // 关联节点
    relatedNodeIds.forEach(nodeId => {
        if (nodeId === centerNodeId) return;

        const nodeInfo = nodesMap[nodeId] || { name: nodeId, type: 'unknown' };
        const isInThreatList = threatNodesList.find(n => n.id === nodeId);

        nodes.push({
            id: nodeId,
            name: nodeInfo.name || nodeId,
            value: 50,
            category: isInThreatList ? 'threat' : 'suspicious',
            itemStyle: {
                color: isInThreatList ? '#f59e0b' : '#60a5fa',
                borderColor: 'rgba(219, 234, 254, 0.74)',
                borderWidth: 2
            },
            symbolSize: isInThreatList ? 25 : 20,
            label: {
                show: showLabels,
                fontSize: 11,
                color: '#dbeafe',
                textBorderColor: 'rgba(3, 10, 24, 0.88)',
                textBorderWidth: 3
            }
        });
    });

    // 构建边数据
    nodeRelations.forEach(rel => {
        links.push({
            source: rel.source,
            target: rel.target,
            value: rel.correlation || 0,
            lineStyle: {
                width: (rel.correlation || 0) * 5,
                opacity: 0.6,
                curveness: 0.1
            }
        });
    });

    const option = {
        backgroundColor: 'transparent',
        tooltip: {
            backgroundColor: 'rgba(8, 18, 38, 0.96)',
            borderColor: 'rgba(125, 178, 255, 0.28)',
            textStyle: { color: '#dbeafe' },
            formatter: function(params) {
                if (params.dataType === 'node') {
                    return `<strong>${params.data.name}</strong><br/>类别: ${params.data.category === 'threat' ? '威胁节点' : '可疑节点'}`;
                } else if (params.dataType === 'edge') {
                    return `关联度: ${(params.data.value * 100).toFixed(1)}%`;
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
                    width: 4
                },
                itemStyle: {
                    borderWidth: 3
                }
            },
            force: {
                repulsion: 300,
                edgeLength: [100, 200],
                gravity: 0.1,
                layoutAnimation: true
            },
            lineStyle: {
                color: 'source',
                curveness: 0.1
            }
        }]
    };

    relationsChart.setOption(option);

    // 窗口调整
    window.addEventListener('resize', () => relationsChart && relationsChart.resize());
}

/**
 * 更新关系详情表格
 */
async function updateRelationsTable(nodeId) {
    const suspiciousRelations = relationsDataCache.suspicious_relations || [];
    const nodeRelations = suspiciousRelations.filter(rel =>
        rel.source === nodeId || rel.target === nodeId
    );

    // 按关联度排序
    nodeRelations.sort((a, b) => (b.correlation || 0) - (a.correlation || 0));

    const tbody = document.getElementById('relationsTableBody');
    const subtitle = document.getElementById('relationsSubtitle');
    if (!tbody) return;

    if (nodeRelations.length === 0) {
        if (subtitle) subtitle.textContent = '当前节点暂无可疑关系记录';
        tbody.innerHTML = `
            <tr>
                <td colspan="5" style="text-align:center; color:#a8b8d2; padding:30px;">
                    该节点暂无可疑关系记录
                </td>
            </tr>
        `;
        return;
    }

    // 获取图数据以获取节点名称
    const graphCache = await DataCache.get('graph');
    const graphData = graphCache?.data || graphCache || {};
    const nodesMap = {};
    if (graphData.nodes) {
        graphData.nodes.forEach(node => {
            nodesMap[node.id] = node;
        });
    }

    if (subtitle) subtitle.textContent = `${nodesMap[nodeId]?.name || nodeId} 的 ${nodeRelations.length} 条可疑关系`;

    tbody.innerHTML = nodeRelations.slice(0, 20).map(rel => {
        const sourceNode = nodesMap[rel.source] || { name: rel.source };
        const targetNode = nodesMap[rel.target] || { name: rel.target };
        const actions = (rel.actions || []).slice(0, 3).join(', ');
        const correlation = rel.correlation || 0;
        const corrClass = correlation > 0.6 ? 'high' : correlation > 0.4 ? 'medium' : 'low';

        return `
            <tr>
                <td>${escapeHtml(sourceNode.name || rel.source)}</td>
                <td>${escapeHtml(targetNode.name || rel.target)}</td>
                <td title="${escapeHtml((rel.actions || []).join(', '))}">${escapeHtml(actions || '-')} ${(rel.actions?.length || 0) > 3 ? '...' : ''}</td>
                <td>${rel.event_count || 0}</td>
                <td><span class="correlation-badge ${corrClass}">${(correlation * 100).toFixed(1)}%</span></td>
            </tr>
        `;
    }).join('');

    if (nodeRelations.length > 20) {
        tbody.innerHTML += `
            <tr>
                <td colspan="5" style="text-align:center; color:#a8b8d2; padding:10px;">
                    ...还有 ${nodeRelations.length - 20} 条关系
                </td>
            </tr>
        `;
    }
}

/**
 * 重置视图
 */
function resetRelationsZoom() {
    if (relationsChart) {
        relationsChart.dispatchAction({ type: 'restore' });
    }
}

/**
 * 切换标签显示
 */
function toggleLabels() {
    showLabels = !showLabels;
    if (relationsChart) {
        relationsChart.setOption({
            series: [{
                label: {
                    show: showLabels
                }
            }]
        });
    }
}

/**
 * 获取威胁等级中文名称
 */
function getThreatLevelName(level) {
    const names = {
        'critical': '严重',
        'high': '高危',
        'medium': '中危',
        'low': '低危',
        'benign': '正常'
    };
    return names[level] || level;
}

/**
 * 获取节点类型标签
 */
function getTypeLabel(type) {
    const labels = {
        'process': '进程',
        'file': '文件',
        'socket': '网络',
        'unknown': '未知'
    };
    return labels[type] || type;
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

function escapeJsString(text) {
    return String(text).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

// 威胁等级颜色
const RELATIONS_LEVEL_COLORS = {
    'critical': '#fb7185',
    'high': '#f59e0b',
    'medium': '#facc15',
    'low': '#34d399',
    'benign': '#94a3b8'
};

// 覆盖main.js中的占位函数
window.TraceEye = window.TraceEye || {};
window.TraceEye.loadRelationsData = loadRelationsData;

// 导出到全局
window.selectThreatNode = selectThreatNode;
window.resetRelationsZoom = resetRelationsZoom;
window.toggleLabels = toggleLabels;
window.executeStep = executeStep;
