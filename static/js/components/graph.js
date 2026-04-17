/**
 * 关系图构建页面组件
 */

// 节点类型颜色配置
const NODE_TYPE_COLORS = {
    'process': '#2196F3',   // 蓝色 - 进程
    'file': '#FF9800',      // 橙色 - 文件
    'socket': '#9C27B0',    // 紫色 - 网络
    'unknown': '#9E9E9E'    // 灰色 - 未知
};

// 节点类型图标配置
const NODE_TYPE_ICONS = {
    'process': 'circle',
    'file': 'rect',
    'socket': 'diamond',
    'unknown': 'circle'
};

// 图表实例
let graphChart = null;

// 组件加载完成后的初始化
window.addEventListener('componentLoaded', (e) => {
    if (e.detail.name === 'graph') {
        initGraphPage();
    }
});

/**
 * 初始化关系图页面
 */
function initGraphPage() {
    // 绑定执行按钮
    const btn = document.getElementById('btnGraph');
    if (btn) {
        btn.addEventListener('click', () => executeStep('graph', '/step/graph'));
    }
}

/**
 * 加载关系图页面数据
 * @param {Object} status - 系统状态
 * @param {Object} pageDataCache - 页面缓存数据
 */
async function loadGraphData(status, pageDataCache) {
    // 检查extract步骤是否完成
    if (status.steps_completed?.extract) {
        document.getElementById('graphInputEmpty').style.display = 'none';
        document.getElementById('graphInputFilled').style.display = 'block';

        // 获取extract步骤的数据作为输入（使用缓存）
        try {
            const extractData = await DataCache.get('extract');
            const data = extractData?.data || {};
            const statistics = data.statistics || {};
            const inEventsEl = document.getElementById('graphInEvents');
            if (inEventsEl) {
                inEventsEl.textContent = statistics.total_events || data.total_events || '-';
            }
        } catch (e) {
            const inEventsEl = document.getElementById('graphInEvents');
            if (inEventsEl) {
                inEventsEl.textContent = '-';
            }
        }

        // 显示输出统计（如果graph已完成）
        if (status.steps_completed?.graph) {
            await loadGraphResults(pageDataCache);
        }
    }
}

/**
 * 加载关系图结果
 * @param {Object} pageDataCache - 页面缓存数据
 */
async function loadGraphResults(pageDataCache) {
    try {
        // 使用传入的缓存数据
        const graphCache = pageDataCache || await DataCache.get('graph');
        const data = graphCache?.data || {};
        const summary = graphCache?.summary || {};

        const outNodesEl = document.getElementById('graphOutNodes');
        const outEdgesEl = document.getElementById('graphOutEdges');
        const outDensityEl = document.getElementById('graphOutDensity');

        if (outNodesEl) outNodesEl.textContent = summary.nodes || summary.node_count || data.node_count || '-';
        if (outEdgesEl) outEdgesEl.textContent = summary.edges || summary.edge_count || data.edge_count || '-';

        // 显示输出区域
        const outputSection = document.getElementById('graphOutputSection');
        if (outputSection) {
            outputSection.style.display = 'block';
        }

        // 显示下载按钮
        const downloadBtn = document.getElementById('downloadGraph');
        if (downloadBtn) {
            downloadBtn.style.display = 'inline-block';
        }

        // 渲染迷你图
        requestAnimationFrame(() => {
            setTimeout(() => {
                renderMiniGraph(data);
            }, 50);
        });
    } catch (e) {
        console.error('Load graph results error:', e);
    }
}

/**
 * 渲染迷你关系图
 */
function renderMiniGraph(graphData) {
    const container = document.getElementById('graphMiniContainer');
    if (!container) {
        console.warn('[Graph] graphMiniContainer not found');
        return;
    }

    console.log('[Graph] renderMiniGraph called, nodes:', graphData.nodes?.length, 'edges:', graphData.edges?.length);

    if (!graphData.nodes || graphData.nodes.length === 0) {
        container.innerHTML = '<p style="text-align:center; padding:50px; color:#999;">暂无数据</p>';
        return;
    }

    // 显示节点类型统计
    displayNodeTypeStats(graphData);

    // 如果容器宽度为0（可能刚从display:none变为显示），延迟渲染
    if (container.clientWidth === 0) {
        console.log('[Graph] Container width is 0, delaying render...');
        setTimeout(() => renderMiniGraph(graphData), 100);
        return;
    }

    console.log('[Graph] Container width:', container.clientWidth, 'height:', container.clientHeight);

    // 检查现有图表实例是否有效（容器是否匹配）
    if (graphChart && graphChart.getDom() !== container) {
        // 容器已变化，销毁旧实例
        console.log('[Graph] Container changed, disposing old instance');
        graphChart.dispose();
        graphChart = null;
    }

    if (!graphChart) {
        graphChart = echarts.init(container);
        console.log('[Graph] ECharts instance initialized');
    } else {
        // 如果实例已存在，先 resize 确保尺寸正确
        graphChart.resize();
        console.log('[Graph] Resized existing chart instance');
    }

    // 关系图构建阶段渲染容量：最多 150 节点 / 300 边
    const MAX_NODES = 150;
    const MAX_EDGES = 300;

    const displayNodes = graphData.nodes.slice(0, MAX_NODES);
    const displayLinks = graphData.edges.slice(0, MAX_EDGES);

    // 计算边权重
    const maxWeight = Math.max(...displayLinks.map(e => e.weight || 1), 1);

    const nodes = displayNodes.map(node => {
        const nodeType = node.type || 'unknown';
        const baseColor = NODE_TYPE_COLORS[nodeType] || NODE_TYPE_COLORS.unknown;

        // 节点大小基于度数
        const baseSize = 12;
        const degreeBonus = Math.min(node.degree || 0, 15);
        const size = baseSize + degreeBonus;

        return {
            id: node.id,
            name: node.name || node.id,
            value: node.degree || 0,
            itemType: nodeType,
            itemStyle: {
                color: baseColor,
                borderColor: '#fff',
                borderWidth: 1
            },
            symbolSize: size,
            symbol: NODE_TYPE_ICONS[nodeType] || 'circle',
            label: {
                show: size > 18,
                formatter: function(params) {
                    const name = params.data.name;
                    return name.length > 15 ? name.substring(0, 12) + '...' : name;
                },
                fontSize: 10,
                color: '#333'
            },
            data: {
                type: nodeType,
                degree: node.degree,
                name: node.name || node.id
            }
        };
    });

    const links = displayLinks.map(edge => {
        const lineWidth = 0.5 + Math.min((edge.weight || 1) / maxWeight * 2, 2);
        return {
            source: edge.source,
            target: edge.target,
            lineStyle: {
                color: '#b0b0b0',
                width: lineWidth,
                opacity: 0.6,
                curveness: 0.1
            },
            value: edge.weight || 1
        };
    });

    const option = {
        tooltip: {
            formatter: function(params) {
                if (params.dataType === 'node') {
                    const d = params.data.data;
                    const typeLabels = {
                        'process': '进程',
                        'file': '文件',
                        'socket': '网络',
                        'unknown': '未知'
                    };
                    return `
                        <div style="padding:8px;">
                            <strong>${d.name}</strong><br/>
                            <span style="color:#666;">类型: ${typeLabels[d.type] || d.type}</span><br/>
                            <span style="color:#666;">连接数: ${d.degree}</span>
                        </div>
                    `;
                } else if (params.dataType === 'edge') {
                    return `权重: ${params.value} 次交互`;
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
                    width: 3,
                    color: '#555'
                },
                itemStyle: {
                    borderWidth: 2,
                    borderColor: '#333'
                }
            },
            force: {
                repulsion: 180,
                edgeLength: [25, 80],
                gravity: 0.15,
                friction: 0.6
            },
            lineStyle: {
                color: 'source',
                curveness: 0.1
            }
        }]
    };

    graphChart.setOption(option, true);
    console.log('[Graph] Chart option set, nodes:', nodes.length, 'links:', links.length);

    // 窗口调整
    window.addEventListener('resize', () => graphChart && graphChart.resize());
}

/**
 * 显示节点类型统计
 */
function displayNodeTypeStats(graphData) {
    const stats = {
        process: 0,
        file: 0,
        socket: 0,
        unknown: 0
    };

    graphData.nodes.forEach(node => {
        const type = node.type || 'unknown';
        if (stats.hasOwnProperty(type)) {
            stats[type]++;
        } else {
            stats.unknown++;
        }
    });

    // 更新显示
    const processCountEl = document.getElementById('processCount');
    const fileCountEl = document.getElementById('fileCount');
    const socketCountEl = document.getElementById('socketCount');
    const unknownCountEl = document.getElementById('unknownCount');
    const nodeTypesStatsEl = document.getElementById('nodeTypesStats');

    if (processCountEl) processCountEl.textContent = stats.process;
    if (fileCountEl) fileCountEl.textContent = stats.file;
    if (socketCountEl) socketCountEl.textContent = stats.socket;
    if (unknownCountEl) unknownCountEl.textContent = stats.unknown;

    // 显示统计区域
    if (nodeTypesStatsEl) {
        nodeTypesStatsEl.style.display = 'flex';
    }
}

/**
 * 执行处理步骤
 */
async function executeStep(pageId, apiEndpoint) {
    try {
        showProcessSection(pageId);
        updateProgress(pageId, 0, '处理中...');

        const result = await apiPost(apiEndpoint);

        if (result.error) {
            throw new Error(result.error);
        }

        updateProgress(pageId, 100, '完成');

        setTimeout(async () => {
            hideProcessSection(pageId);
            DataCache.clear(pageId);
            await loadPageData(pageId);
        }, 500);

    } catch (error) {
        hideProcessSection(pageId);
        alert(`处理失败: ${error.message}`);
    }
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

// 覆盖main.js中的占位函数
window.TraceEye = window.TraceEye || {};
window.TraceEye.loadGraphData = loadGraphData;
window.executeStep = executeStep;
