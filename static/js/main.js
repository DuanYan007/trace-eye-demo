// ==================== 全局变量 ====================
let graphChart = null;
let relationsChart = null;
let currentPage = null;
let pollInterval = null;

// 关系挖掘分页状态
let relationsPagination = {
    page: 1,
    pageSize: 20,
    total: 0,
    totalPages: 1,
    relations: []
};

// 关系图配置
let relationsGraphConfig = {
    showLabels: true,
    maxNodes: 100,
    maxEdges: 200
};

// 告警分页状态
let alertsPagination = {
    page: 1,
    pageSize: 20,
    total: 0,
    totalPages: 1
};

// 页面配置
const PAGES = ['upload', 'extract', 'graph', 'rules', 'threat', 'relations', 'chains'];

// 页面依赖关系
const PAGE_DEPENDENCIES = {
    'upload': [],
    'extract': ['upload'],
    'graph': ['extract'],
    'rules': ['graph'],
    'threat': ['rules'],
    'relations': ['threat'],
    'chains': ['relations']
};

// 数据缓存
let pageData = {};

// ==================== 工具函数 ====================

function formatTimestamp(ts) {
    if (!ts) return '-';
    try {
        const date = new Date(ts);
        return date.toLocaleString('zh-CN');
    } catch {
        return ts;
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ==================== API 调用 ====================

async function apiRequest(url, options = {}) {
    try {
        if (options.method === 'POST' && !options.headers) {
            options.headers = {
                'Content-Type': 'application/json'
            };
        }
        if (options.body && typeof options.body === 'object') {
            options.body = JSON.stringify(options.body);
        }

        const response = await fetch(url, options);
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || '请求失败');
        }
        return data;
    } catch (error) {
        console.error('API 请求错误:', error);
        throw error;
    }
}

// ==================== 页面导航 ====================

function navigateTo(pageId) {
    // 切换页面
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.getElementById(`page-${pageId}`).classList.add('active');

    // 更新导航状态
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelector(`[data-page="${pageId}"]`).classList.add('active');

    // 更新顶部标题
    const titles = {
        'upload': '数据准备',
        'extract': '事件提取',
        'graph': '关系图构建',
        'rules': '规则检测',
        'threat': '威胁检测',
        'relations': '关系挖掘',
        'chains': '攻击链重建'
    };
    document.getElementById('currentStepName').textContent = titles[pageId] || '';

    currentPage = pageId;

    // 加载页面数据
    loadPageData(pageId);
}

// ==================== 加载页面数据 ====================

async function loadPageData(pageId) {
    try {
        const status = await apiRequest('/api/status');

        // 转换 steps_status 格式到 steps_completed 格式
        const stepsCompleted = {};
        if (status.steps_status) {
            for (const [stepId, stepInfo] of Object.entries(status.steps_status)) {
                stepsCompleted[stepId] = stepInfo.completed;
            }
        }

        // 将转换后的格式附加到 status 对象
        status.steps_completed = stepsCompleted;

        // 检查依赖
        const dependencies = PAGE_DEPENDENCIES[pageId] || [];
        const canProceed = dependencies.every(dep => stepsCompleted[dep]);

        if (!canProceed && dependencies.length > 0) {
            // upload页面没有InputEmpty/InputFilled结构，跳过
            if (pageId !== 'upload') {
                showInputEmpty(pageId, dependencies[dependencies.length - 1]);
            }
            return;
        }

        // 隐藏空状态，显示已填充状态（upload页面跳过）
        if (pageId !== 'upload') {
            hideInputEmpty(pageId);
        }

        // 根据页面加载不同数据
        switch (pageId) {
            case 'upload':
                await loadUploadData(status);
                break;
            case 'extract':
                await loadExtractData(status);
                break;
            case 'graph':
                await loadGraphData(status);
                break;
            case 'rules':
                await loadRulesData(status);
                break;
            case 'threat':
                await loadThreatData(status);
                break;
            case 'relations':
                await loadRelationsData(status);
                break;
            case 'chains':
                await loadChainsData(status);
                break;
            case 'ai':
                await loadAIData(status);
                break;
        }

    } catch (error) {
        console.error(`加载页面 ${pageId} 数据失败:`, error);
    }
}

// ==================== 页面数据加载函数 ====================

async function loadUploadData(status) {
    // 检查是否有数据（通过检查 upload 步骤是否完成）
    try {
        const isUploadComplete = status.steps_completed?.upload;

        if (isUploadComplete) {
            // 隐藏上传区域，显示结果区域
            document.getElementById('uploadEmpty').style.display = 'none';
            document.getElementById('uploadFileList').style.display = 'none';
            document.getElementById('uploadResultSection').style.display = 'block';

            // 显示下载按钮
            showDownloadButton('upload');

            // 获取并显示文件列表
            await displayUploadedFiles();
        } else {
            // 显示上传区域
            document.getElementById('uploadEmpty').style.display = 'block';
            document.getElementById('uploadResultSection').style.display = 'none';
        }
    } catch (error) {
        console.error('loadUploadData error:', error);
    }
}

async function displayUploadedFiles() {
    // 显示已上传的日志文件列表
    try {
        // 获取日志文件信息
        const response = await fetch('/api/logs/info');
        if (!response.ok) return;

        const data = await response.json();
        const filesList = document.getElementById('uploadedFilesList');

        if (data.files && data.files.length > 0) {
            // 更新文件计数
            document.getElementById('uploadedFileCount').textContent = data.files.length;

            filesList.innerHTML = data.files.map(file => `
                <div style="display: flex; align-items: center; gap: 15px; padding: 12px; background: var(--light-bg); border-radius: 6px;">
                    <span style="font-size: 1.5rem;">${getFileIcon(file.type)}</span>
                    <div style="flex: 1;">
                        <div style="font-weight: 500;">${escapeHtml(file.filename)}</div>
                        <div style="font-size: 0.85rem; color: var(--text-secondary);">
                            ${getTypeLabel(file.type)} | ${file.line_count.toLocaleString()} 行
                        </div>
                    </div>
                    <span style="font-size: 0.85rem; color: var(--success-color);">✓</span>
                </div>
            `).join('');
        } else {
            filesList.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 20px;">暂无日志文件</p>';
            document.getElementById('uploadedFileCount').textContent = '0';
        }
    } catch (error) {
        console.error('displayUploadedFiles error:', error);
    }
}

function getFileIcon(type) {
    const icons = {
        'process': '⚙️',
        'file': '📄',
        'network': '🌐',
        'json': '📋'
    };
    return icons[type] || '📁';
}

function getTypeLabel(type) {
    const labels = {
        'process': '进程日志',
        'file': '文件日志',
        'network': '网络日志',
        'json': 'JSON日志'
    };
    return labels[type] || '未知类型';
}

async function loadExtractData(status) {
    // 检查upload步骤是否完成
    if (status.steps_completed?.upload) {
        document.getElementById('extractInputEmpty').style.display = 'none';
        document.getElementById('extractInputFilled').style.display = 'block';

        // 从缓存获取upload步骤的数据作为输入，显示文件列表
        try {
            const uploadCache = await apiRequest('/api/cache/upload');
            const files = uploadCache.data?.files || [];

            const fileListDiv = document.getElementById('extractInputFileList');
            if (files.length > 0) {
                fileListDiv.innerHTML = files.map(file => `
                    <div style="display: flex; align-items: center; gap: 10px; padding: 8px 12px; background: var(--light-bg); border-radius: 4px; font-size: 0.9rem;">
                        <span>${getFileIcon(file.type)}</span>
                        <span style="flex: 1;">${escapeHtml(file.filename)}</span>
                        <span style="color: var(--text-secondary);">${file.line_count?.toLocaleString() || 0} 行</span>
                    </div>
                `).join('');
            } else {
                fileListDiv.innerHTML = '<p style="color: var(--text-secondary);">暂无文件</p>';
            }
        } catch (e) {
            console.error('Load upload cache error:', e);
            document.getElementById('extractInputFileList').innerHTML = '<p style="color: var(--text-secondary);">无法加载文件信息</p>';
        }

        showOutputSection('extract');

        // 显示输出统计（如果extract已完成）
        if (status.steps_completed?.extract) {
            // 从缓存获取extract步骤的数据
            try {
                const extractCache = await apiRequest('/api/cache/extract');
                const data = extractCache.data || {};
                const summary = extractCache.summary || {};

                const totalCount = summary.total_events || data.total_events || 0;
                document.getElementById('extractOutTotal').textContent = totalCount;
                document.getElementById('extractEventCount').textContent = totalCount;

                // 类型分布
                const byType = summary.by_type || data.by_type || {};
                const typeBars = document.getElementById('extractTypeBars');
                if (Object.keys(byType).length > 0) {
                    const maxCount = Math.max(...Object.values(byType), 1);
                    typeBars.innerHTML = Object.entries(byType).map(([type, count]) => `
                        <div class="type-bar-item">
                            <span class="type-bar-label">${type}</span>
                            <div class="type-bar-track">
                                <div class="type-bar-fill" style="width: ${(count / maxCount * 100)}%"></div>
                            </div>
                            <span class="type-bar-value">${count.toLocaleString()}</span>
                        </div>
                    `).join('');
                } else {
                    typeBars.innerHTML = '<p style="color: var(--text-secondary);">暂无数据</p>';
                }

                // 显示下载按钮
                showDownloadButton('extract');
            } catch (e) {
                console.error('Load extract cache error:', e);
            }
        }
    }
}

async function loadGraphData(status) {
    // 检查extract步骤是否完成
    if (status.steps_completed?.extract) {
        document.getElementById('graphInputEmpty').style.display = 'none';
        document.getElementById('graphInputFilled').style.display = 'block';

        // 从缓存获取extract步骤的数据作为输入
        try {
            const extractCache = await apiRequest('/api/cache/extract');
            const data = extractCache.data || {};
            document.getElementById('graphInEvents').textContent = data.total_events || '-';
        } catch (e) {
            document.getElementById('graphInEvents').textContent = '-';
        }

        // 显示输出统计（如果graph已完成）
        if (status.steps_completed?.graph) {
            showOutputSection('graph');

            try {
                const graphCache = await apiRequest('/api/cache/graph');
                const data = graphCache.data || {};
                const summary = graphCache.summary || {};

                document.getElementById('graphOutNodes').textContent = summary.nodes || data.node_count || '-';
                document.getElementById('graphOutEdges').textContent = summary.edges || data.edge_count || '-';

                // 获取完整图数据用于渲染迷你图
                const graphData = await apiRequest('/api/graph');
                document.getElementById('graphOutDensity').textContent = (graphData.statistics?.density || 0).toFixed(4);

                // 渲染迷你图
                renderMiniGraph(graphData);

                // 显示下载按钮
                showDownloadButton('graph');
            } catch (e) {
                console.error('Load graph cache error:', e);
            }
        }
    }
}

async function loadRulesData(status) {
    // 检查graph步骤是否完成
    if (status.steps_completed?.graph) {
        document.getElementById('rulesInputEmpty').style.display = 'none';
        document.getElementById('rulesInputFilled').style.display = 'block';

        // 从缓存获取graph步骤的数据作为输入
        try {
            const graphCache = await apiRequest('/api/cache/graph');
            const data = graphCache.data || {};
            document.getElementById('rulesInNodes').textContent = data.node_count || '-';
            document.getElementById('rulesInEdges').textContent = data.edge_count || '-';
        } catch (e) {
            document.getElementById('rulesInNodes').textContent = '-';
            document.getElementById('rulesInEdges').textContent = '-';
        }

        // 显示输出统计（如果rules已完成）
        if (status.steps_completed?.rules) {
            showOutputSection('rules');

            try {
                const rulesCache = await apiRequest('/api/cache/rules');
                const data = rulesCache.data || {};
                const summary = rulesCache.summary || {};

                const bySeverity = summary.by_severity || data.by_severity || {};

                document.getElementById('rulesOutHigh').textContent = bySeverity.high || 0;
                document.getElementById('rulesOutMedium').textContent = bySeverity.medium || 0;
                document.getElementById('rulesOutLow').textContent = bySeverity.low || 0;

                // 加载告警（使用分页）
                await loadAlertsPage(1);

                // 显示下载按钮
                showDownloadButton('rules');
            } catch (e) {
                console.error('Load rules cache error:', e);
            }
        }
    }
}

// 加载告警分页数据
async function loadAlertsPage(page) {
    try {
        const response = await apiRequest(`/api/alerts?page=${page}&page_size=20`);
        const { alerts, total, page: currentPage, total_pages } = response;

        // 更新分页状态
        alertsPagination = {
            page: currentPage,
            pageSize: 20,
            total: total,
            totalPages: total_pages
        };

        // 渲染告警列表
        const preview = document.getElementById('rulesAlertsPreview');
        if (alerts.length > 0) {
            preview.innerHTML = alerts.map(alert => `
                <div class="alert-item-mini ${alert.rule?.severity || 'low'}">
                    <div style="display: flex; justify-content: space-between; align-items: start;">
                        <div>
                            <strong>[${escapeHtml(alert.rule?.rule_id || '')}]</strong>
                            <span style="margin-left: 8px;">${escapeHtml(alert.rule?.rule_name || '')}</span>
                        </div>
                        <span style="font-size: 0.75rem; color: var(--text-secondary);">${alert.timestamp?.split('T')[1]?.substring(0, 8) || ''}</span>
                    </div>
                    ${alert.message ? `<div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 4px;">${escapeHtml(alert.message.substring(0, 100))}${alert.message.length > 100 ? '...' : ''}</div>` : ''}
                </div>
            `).join('');
        } else {
            preview.innerHTML = '<p style="color: var(--text-secondary); padding: 10px;">暂无告警</p>';
        }

        // 更新分页控件
        updatePaginationControls();

    } catch (e) {
        console.error('Load alerts page error:', e);
    }
}

// 更新分页控件状态
function updatePaginationControls() {
    const pagination = document.getElementById('rulesPagination');
    const prevBtn = document.getElementById('rulesPrevPage');
    const nextBtn = document.getElementById('rulesNextPage');
    const pageInfo = document.getElementById('rulesPageInfo');

    if (alertsPagination.total > 0) {
        pagination.style.display = 'flex';
        pageInfo.textContent = `第 ${alertsPagination.page} / ${alertsPagination.totalPages} 页 (共 ${alertsPagination.total} 条)`;
        prevBtn.disabled = alertsPagination.page <= 1;
        nextBtn.disabled = alertsPagination.page >= alertsPagination.totalPages;
    } else {
        pagination.style.display = 'none';
    }
}

// 绑定分页按钮事件
document.getElementById('rulesPrevPage')?.addEventListener('click', () => {
    if (alertsPagination.page > 1) {
        loadAlertsPage(alertsPagination.page - 1);
    }
});

document.getElementById('rulesNextPage')?.addEventListener('click', () => {
    if (alertsPagination.page < alertsPagination.totalPages) {
        loadAlertsPage(alertsPagination.page + 1);
    }
});

async function loadThreatData(status) {
    // 检查rules步骤是否完成
    if (status.steps_completed?.rules) {
        document.getElementById('threatInputEmpty').style.display = 'none';
        document.getElementById('threatInputFilled').style.display = 'block';

        // 从缓存获取rules步骤的数据作为输入
        let rulesCache = null;
        try {
            rulesCache = await apiRequest('/api/cache/rules');
            const data = rulesCache.data || {};
            document.getElementById('threatInAlerts').textContent = data.total_alerts || '-';
        } catch (e) {
            document.getElementById('threatInAlerts').textContent = '-';
        }

        // 获取graph数据用于节点数
        try {
            const graphCache = await apiRequest('/api/cache/graph');
            document.getElementById('threatInNodes').textContent = graphCache.data?.node_count || '-';
        } catch (e) {
            document.getElementById('threatInNodes').textContent = '-';
        }

        // 显示输出统计（如果threat已完成）
        if (status.steps_completed?.threat) {
            showOutputSection('threat');

            try {
                const threatCache = await apiRequest('/api/cache/threat');
                const data = threatCache.data || {};
                const summary = threatCache.summary || {};

                // 总节点数（从graph缓存获取）
                const graphCache = await apiRequest('/api/cache/graph');
                document.getElementById('threatTotalNodes').textContent = graphCache.data?.node_count || 0;

                // 异常节点数
                document.getElementById('threatAnomalies').textContent = data.anomaly_count || summary.anomaly_count || 0;

                // 恶意事件数（从rules缓存获取）
                document.getElementById('threatMaliciousEvents').textContent = rulesCache?.data?.total_alerts || 0;

                // 节点分类统计 - 直接使用 summary.by_level（最可靠的数据源）
                const byLevel = summary.by_level || data.summary?.by_level || {};
                const critical = byLevel.critical || 0;
                const high = byLevel.high || 0;
                const medium = byLevel.medium || 0;
                const low = byLevel.low || 0;

                document.getElementById('threatCritical').textContent = critical;
                document.getElementById('threatHigh').textContent = high;
                document.getElementById('threatMedium').textContent = medium;
                document.getElementById('threatLow').textContent = low;

                const total = critical + high + medium + low;
                const safeTotal = total || 1;
                document.getElementById('threatCriticalBar').style.width = `${(critical / safeTotal * 100)}%`;
                document.getElementById('threatHighBar').style.width = `${(high / safeTotal * 100)}%`;
                document.getElementById('threatMediumBar').style.width = `${(medium / safeTotal * 100)}%`;
                document.getElementById('threatLowBar').style.width = `${(low / safeTotal * 100)}%`;

                // 威胁等级
                const threatIcon = document.getElementById('threatIcon');
                const threatText = document.getElementById('threatLevelText');
                const threatDesc = document.getElementById('threatLevelDesc');

                const level = summary.overall_threat_level || data.overall_threat_level || 'unknown';
                const levelConfig = {
                    'critical': { icon: '🔴', text: '严重威胁', desc: '检测到严重安全威胁，建议立即处理' },
                    'high': { icon: '🟠', text: '高危威胁', desc: '检测到高危可疑活动，需要关注' },
                    'medium': { icon: '🟡', text: '中等威胁', desc: '存在一些可疑行为，建议调查' },
                    'low': { icon: '🟢', text: '低危威胁', desc: '存在轻微异常行为' },
                    'benign': { icon: '🟢', text: '正常', desc: '未检测到明显威胁' }
                };

                const config = levelConfig[level] || levelConfig['benign'];
                threatIcon.textContent = config.icon;
                threatText.textContent = config.text;
                threatDesc.textContent = config.desc;

                // 渲染高风险节点表格
                const classified = data.classified_nodes || {};
                await renderHighRiskNodes(classified);

                // 显示下载按钮
                showDownloadButton('threat');
            } catch (e) {
                console.error('Load threat cache error:', e);
            }
        }
    }
}

// 渲染高风险节点表格
async function renderHighRiskNodes(classified) {
    const tableBody = document.getElementById('threatNodesTable');

    // 收集所有威胁节点（critical + high + medium），按优先级排序
    const allThreatNodes = [
        ...(classified.critical || []).map(id => ({ id, level: 'critical' })),
        ...(classified.high || []).map(id => ({ id, level: 'high' })),
        ...(classified.medium || []).map(id => ({ id, level: 'medium' }))
    ];

    // 只显示前30个（避免页面过长）
    const displayNodes = allThreatNodes.slice(0, 30);

    if (displayNodes.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-secondary);padding:20px;">暂无威胁节点</td></tr>';
        return;
    }

    // 获取图数据来获取节点详情
    try {
        const graphCache = await apiRequest('/api/cache/graph');
        const nodes = graphCache.data?.nodes || [];
        const nodeMap = new Map(nodes.map(n => [n.id, n]));

        // 获取威胁分数
        const threatCache = await apiRequest('/api/cache/threat');
        const threatScores = threatCache.data?.threat_scores || {};
        const anomalyScores = threatCache.data?.anomaly_detection?.scores || {};

        tableBody.innerHTML = displayNodes.map(({ id, level }) => {
            const node = nodeMap.get(id) || {};
            const name = node.name || id;
            const type = node.type || 'unknown';
            // 优先使用威胁分数，其次使用异常分数
            const score = threatScores[id] !== undefined ? threatScores[id] :
                         anomalyScores[id] !== undefined ? anomalyScores[id] : '-';

            return `
                <tr>
                    <td>${escapeHtml(name)}</td>
                    <td>${getNodeTypeLabel(type)}</td>
                    <td><span style="color:${getScoreColor(score)}">${typeof score === 'number' ? score.toFixed(2) : score}</span></td>
                    <td><span class="node-severity ${level}">${getSeverityLabel(level)}</span></td>
                </tr>
            `;
        }).join('');

        // 如果还有更多节点未显示，添加提示
        if (allThreatNodes.length > 30) {
            const hintRow = `<tr><td colspan="4" style="text-align:center;color:var(--text-secondary);font-size:0.85rem;padding:8px;">
                还有 ${allThreatNodes.length - 30} 个威胁节点未显示...
            </td></tr>`;
            tableBody.innerHTML += hintRow;
        }
    } catch (e) {
        console.error('Render high risk nodes error:', e);
    }
}

function getSeverityLabel(level) {
    const labels = {
        'critical': '严重',
        'high': '高危',
        'medium': '中等',
        'low': '低危',
        'benign': '正常'
    };
    return labels[level] || level.toUpperCase();
}

function getNodeTypeLabel(type) {
    const labels = {
        'process': '⚙️ 进程',
        'file': '📄 文件',
        'socket': '🌐 网络',
        'unknown': '❓ 未知'
    };
    return labels[type] || type;
}

function getScoreColor(score) {
    if (score === '-') return '#999';
    if (score > 0.8) return '#f44336';
    if (score > 0.6) return '#ff9800';
    if (score > 0.4) return '#ffc107';
    return '#4CAF50';
}

async function loadRelationsData(status) {
    // 检查threat步骤是否完成
    if (status.steps_completed?.threat) {
        document.getElementById('relationsInputEmpty').style.display = 'none';
        document.getElementById('relationsInputFilled').style.display = 'block';

        // 从缓存获取threat步骤的数据作为输入
        try {
            const threatCache = await apiRequest('/api/cache/threat');
            const data = threatCache.data || {};
            document.getElementById('relationsInAnomalies').textContent = data.anomaly_count || '-';
        } catch (e) {
            document.getElementById('relationsInAnomalies').textContent = '-';
        }

        // 获取graph数据用于节点数
        try {
            const graphCache = await apiRequest('/api/cache/graph');
            document.getElementById('relationsInNodes').textContent = graphCache.data?.node_count || '-';
        } catch (e) {
            document.getElementById('relationsInNodes').textContent = '-';
        }

        // 显示输出统计（如果relations已完成）
        if (status.steps_completed?.relations) {
            showOutputSection('relations');

            try {
                // 获取完整的关系数据
                const relationsData = await apiRequest('/api/relations');

                // 更新统计卡片
                const stats = relationsData.statistics || {};
                document.getElementById('relationsOutTotal').textContent = stats.total_relations || 0;
                document.getElementById('relationsOutSubgraphs').textContent = stats.total_subgraphs || 0;
                document.getElementById('relationsOutCorrelation').textContent =
                    (stats.avg_correlation || 0).toFixed(3);

                // 计算高风险关系数（关联度 > 0.7）
                const highRiskCount = (relationsData.suspicious_relations || [])
                    .filter(r => r.correlation > 0.7).length;
                document.getElementById('relationsOutHighRisk').textContent = highRiskCount;

                // 加载并显示可疑关系列表
                await loadSuspiciousRelations(relationsData.suspicious_relations || []);

                // 加载并显示可疑子图
                displaySuspiciousSubgraphs(relationsData.suspicious_subgraphs || []);

                // 渲染关系网络图
                await renderRelationsGraph(relationsData);

                // 显示下载按钮
                showDownloadButton('relations');
            } catch (e) {
                console.error('Load relations cache error:', e);
            }
        }
    }
}

// 加载可疑关系列表（分页）
async function loadSuspiciousRelations(relations) {
    // 保存所有关系
    relationsPagination.relations = relations;
    relationsPagination.total = relations.length;
    relationsPagination.totalPages = Math.ceil(relations.length / relationsPagination.pageSize) || 1;
    relationsPagination.page = 1;

    await renderRelationsPage();
}

// 渲染关系列表当前页
async function renderRelationsPage() {
    const { relations, page, pageSize } = relationsPagination;
    const startIdx = (page - 1) * pageSize;
    const endIdx = startIdx + pageSize;
    const pageRelations = relations.slice(startIdx, endIdx);

    const listContainer = document.getElementById('suspiciousRelationsList');
    const pagination = document.getElementById('relationsPagination');

    if (!pageRelations || pageRelations.length === 0) {
        listContainer.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 20px;">暂无可疑关系</p>';
        pagination.style.display = 'none';
        return;
    }

    // 获取节点信息用于显示名称
    let nodeInfoMap = new Map();
    try {
        const graphData = await apiRequest('/api/graph');
        (graphData.nodes || []).forEach(node => {
            nodeInfoMap.set(node.id, {
                name: node.name || node.id,
                type: node.type || 'unknown'
            });
        });
    } catch (e) {
        console.error('Failed to load graph data:', e);
    }

    // 渲染关系列表
    listContainer.innerHTML = pageRelations.map(rel => {
        const sourceInfo = nodeInfoMap.get(rel.source) || { name: rel.source, type: 'unknown' };
        const targetInfo = nodeInfoMap.get(rel.target) || { name: rel.target, type: 'unknown' };

        const correlationClass = rel.correlation > 0.7 ? 'high' : rel.correlation > 0.5 ? 'medium' : 'low';
        const itemClass = rel.correlation > 0.7 ? 'high' : rel.correlation > 0.5 ? 'medium' : 'low';

        return `
            <div class="relation-item ${itemClass}">
                <div class="relation-source">
                    <span class="relation-node-type ${sourceInfo.type}">${getTypeIcon(sourceInfo.type)}</span>
                    <span class="relation-node-name" title="${escapeHtml(sourceInfo.name)}">${escapeHtml(truncateName(sourceInfo.name, 15))}</span>
                </div>
                <span class="relation-arrow">→</span>
                <div class="relation-target">
                    <span class="relation-node-type ${targetInfo.type}">${getTypeIcon(targetInfo.type)}</span>
                    <span class="relation-node-name" title="${escapeHtml(targetInfo.name)}">${escapeHtml(truncateName(targetInfo.name, 15))}</span>
                </div>
                <div class="relation-correlation">
                    <span class="relation-correlation-value ${correlationClass}">${rel.correlation.toFixed(2)}</span>
                    <span class="relation-correlation-label">关联度</span>
                </div>
            </div>
        `;
    }).join('');

    // 更新分页控件
    if (relationsPagination.total > pageSize) {
        pagination.style.display = 'flex';
        document.getElementById('relationsPageInfo').textContent =
            `第 ${page} / ${relationsPagination.totalPages} 页 (共 ${relationsPagination.total} 条)`;
        document.getElementById('relationsPrevPage').disabled = page <= 1;
        document.getElementById('relationsNextPage').disabled = page >= relationsPagination.totalPages;
    } else {
        pagination.style.display = 'none';
    }
}

// 获取类型图标
function getTypeIcon(type) {
    const icons = {
        'process': '⚙️',
        'file': '📄',
        'socket': '🌐',
        'unknown': '❓'
    };
    return icons[type] || '❓';
}

// 截断名称
function truncateName(name, maxLength) {
    if (!name || name.length <= maxLength) return name || '-';
    return name.substring(0, maxLength) + '...';
}

// 分页按钮事件
document.getElementById('relationsPrevPage')?.addEventListener('click', () => {
    if (relationsPagination.page > 1) {
        relationsPagination.page--;
        renderRelationsPage();
    }
});

document.getElementById('relationsNextPage')?.addEventListener('click', () => {
    if (relationsPagination.page < relationsPagination.totalPages) {
        relationsPagination.page++;
        renderRelationsPage();
    }
});

// 显示可疑子图
async function displaySuspiciousSubgraphs(subgraphs) {
    const container = document.getElementById('suspiciousSubgraphsList');

    if (!subgraphs || subgraphs.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 20px; grid-column: 1 / -1;">暂无可疑子图</p>';
        return;
    }

    // 按威胁评分排序，取前8个
    const sortedSubgraphs = subgraphs
        .sort((a, b) => (b.threat_score || 0) - (a.threat_score || 0))
        .slice(0, 8);

    container.innerHTML = sortedSubgraphs.map(subgraph => {
        const threatClass = subgraph.threat_score > 0.7 ? 'high' : subgraph.threat_score > 0.4 ? 'medium' : 'low';
        const threatLabel = subgraph.threat_score > 0.7 ? '高危' : subgraph.threat_score > 0.4 ? '中危' : '低危';

        // 预览节点（最多显示5个）
        const nodePreview = (subgraph.nodes || []).slice(0, 5);

        return `
            <div class="subgraph-card">
                <div class="subgraph-card-header">
                    <span class="subgraph-id">子图 #${escapeHtml(subgraph.id?.replace('subgraph_', '') || 'N/A')}</span>
                    <span class="subgraph-threat ${threatClass}">${threatLabel}</span>
                </div>
                <div class="subgraph-stats">
                    <span class="subgraph-stat">
                        <span>🔢</span>
                        <span>${subgraph.node_count || 0} 节点</span>
                    </span>
                    <span class="subgraph-stat">
                        <span>🔗</span>
                        <span>${subgraph.edge_count || 0} 边</span>
                    </span>
                    <span class="subgraph-stat">
                        <span>⚠️</span>
                        <span>${(subgraph.threat_score * 100).toFixed(0)}% 威胁</span>
                    </span>
                </div>
                <div class="subgraph-nodes-preview">
                    <div class="subgraph-nodes-list">
                        ${nodePreview.map(nodeId =>
                            `<span class="subgraph-node-tag">${escapeHtml(truncateName(nodeId, 12))}</span>`
                        ).join('')}
                        ${(subgraph.nodes?.length || 0) > 5 ? `<span class="subgraph-node-tag">+${subgraph.nodes.length - 5} 更多</span>` : ''}
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

// 渲染关系网络图
async function renderRelationsGraph(relationsData) {
    const container = document.getElementById('relationsGraphContainer');
    if (!container || container.clientWidth === 0) return;

    if (!relationsData.suspicious_relations || relationsData.suspicious_relations.length === 0) {
        container.innerHTML = '<p style="text-align:center; padding:50px; color:#999;">暂无可疑关系数据</p>';
        return;
    }

    // 初始化 ECharts
    if (!relationsChart) {
        relationsChart = echarts.init(container);
    }

    // 获取图数据和异常节点
    let graphData, anomalyNodes;
    try {
        graphData = await apiRequest('/api/graph');
        const threatData = await apiRequest('/api/threat');
        anomalyNodes = new Set(threatData.anomaly_detection?.anomaly_nodes || []);
    } catch (e) {
        console.error('Failed to load data for relations graph:', e);
        return;
    }

    // 构建节点集合（异常节点 + 可疑关系中的节点）
    const nodeSet = new Set(anomalyNodes);
    const relations = relationsData.suspicious_relations.slice(0, relationsGraphConfig.maxEdges);

    relations.forEach(rel => {
        nodeSet.add(rel.source);
        nodeSet.add(rel.target);
    });

    // 限制节点数量
    const limitedNodes = Array.from(nodeSet).slice(0, relationsGraphConfig.maxNodes);

    // 构建节点数据
    const nodes = limitedNodes.map(nodeId => {
        const node = (graphData.nodes || []).find(n => n.id === nodeId) || {};
        const isAnomaly = anomalyNodes.has(nodeId);
        const isInRelations = relations.some(r => r.source === nodeId || r.target === nodeId);

        let category = 0; // 普通
        if (isAnomaly) category = 2; // 异常
        else if (isInRelations) category = 1; // 可疑

        const nodeType = node.type || 'unknown';
        const baseColor = category === 2 ? '#f44336' :
                         category === 1 ? '#ff9800' :
                         NODE_TYPE_COLORS[nodeType] || '#2196F3';

        return {
            id: nodeId,
            name: node.name || nodeId,
            value: node.degree || 1,
            category: category,
            symbolSize: isAnomaly ? 20 : (category === 1 ? 15 : 10),
            itemStyle: {
                color: baseColor
            },
            label: {
                show: relationsGraphConfig.showLabels,
                formatter: function(params) {
                    const name = params.data.name;
                    return name.length > 10 ? name.substring(0, 8) + '...' : name;
                }
            }
        };
    });

    // 构建边数据
    const links = relations.map(rel => {
        return {
            source: rel.source,
            target: rel.target,
            value: rel.correlation,
            lineStyle: {
                width: Math.max(1, rel.correlation * 3),
                color: rel.correlation > 0.7 ? '#f44336' :
                       rel.correlation > 0.5 ? '#ff9800' : '#999',
                opacity: 0.6
            }
        };
    });

    const option = {
        tooltip: {
            formatter: function(params) {
                if (params.dataType === 'node') {
                    const category = params.data.category === 2 ? '异常' :
                                   params.data.category === 1 ? '可疑' : '普通';
                    return `
                        <div style="padding:8px;">
                            <strong>${escapeHtml(params.data.name)}</strong><br/>
                            <span style="color:#666;">类型: ${category}</span><br/>
                            <span style="color:#666;">度数: ${params.data.value}</span>
                        </div>
                    `;
                } else if (params.dataType === 'edge') {
                    return `关联度: ${(params.data.value * 100).toFixed(1)}%`;
                }
            }
        },
        legend: [{
            data: ['普通节点', '可疑节点', '异常节点'],
            top: 10,
            right: 10
        }],
        series: [{
            type: 'graph',
            layout: 'force',
            data: nodes,
            links: links,
            categories: [
                { name: '普通节点', itemStyle: { color: '#2196F3' } },
                { name: '可疑节点', itemStyle: { color: '#ff9800' } },
                { name: '异常节点', itemStyle: { color: '#f44336' } }
            ],
            roam: true,
            draggable: true,
            focusNodeAdjacency: true,
            emphasis: {
                focus: 'adjacency',
                lineStyle: {
                    width: 4
                }
            },
            force: {
                repulsion: 200,
                edgeLength: [50, 150],
                gravity: 0.1
            },
            lineStyle: {
                curveness: 0.1
            }
        }]
    };

    relationsChart.setOption(option, true);

    // 窗口调整
    window.removeEventListener('resize', onRelationsGraphResize);
    window.addEventListener('resize', onRelationsGraphResize);
}

function onRelationsGraphResize() {
    if (relationsChart) {
        relationsChart.resize();
    }
}

// 关系图控制按钮
document.getElementById('btnResetGraphView')?.addEventListener('click', () => {
    if (relationsChart) {
        relationsChart.dispatchAction({
            type: 'restore'
        });
    }
});

document.getElementById('btnToggleLabels')?.addEventListener('click', async () => {
    relationsGraphConfig.showLabels = !relationsGraphConfig.showLabels;

    // 重新加载当前页数据以刷新图表
    try {
        const status = await apiRequest('/api/status');
        if (status.steps_completed?.relations) {
            const relationsData = await apiRequest('/api/relations');
            await renderRelationsGraph(relationsData);
        }
    } catch (e) {
        console.error('Failed to toggle labels:', e);
    }
});

async function loadChainsData(status) {
    // 检查relations步骤是否完成
    if (status.steps_completed?.relations) {
        document.getElementById('chainsInputEmpty').style.display = 'none';
        document.getElementById('chainsInputFilled').style.display = 'block';

        // 从缓存获取relations步骤的数据作为输入
        try {
            const relationsCache = await apiRequest('/api/cache/relations');
            const data = relationsCache.data || {};
            document.getElementById('chainsInRelations').textContent = data.relation_count || '-';
        } catch (e) {
            document.getElementById('chainsInRelations').textContent = '-';
        }

        // 获取rules数据用于告警数
        try {
            const rulesCache = await apiRequest('/api/cache/rules');
            document.getElementById('chainsInAlerts').textContent = rulesCache.data?.total_alerts || '-';
        } catch (e) {
            document.getElementById('chainsInAlerts').textContent = '-';
        }

        // 显示输出统计（如果chains已完成）
        if (status.steps_completed?.chains) {
            showOutputSection('chains');

            try {
                const chainsCache = await apiRequest('/api/cache/chains');
                const data = chainsCache.data || {};
                const summary = chainsCache.summary || {};

                document.getElementById('chainsOutTotal').textContent = summary.chains || data.chain_count || 0;

                const chains = data.attack_chains || [];
                const preview = document.getElementById('chainsListPreview');
                if (chains.length > 0) {
                    preview.innerHTML = chains.slice(0, 3).map(chain => `
                        <div class="chain-item-mini">
                            <div class="chain-name">${escapeHtml(chain.attack_type || '未知攻击类型')}</div>
                            <div class="chain-info">威胁评分: ${((chain.threat_score || 0) * 100).toFixed(1)}% | 节点: ${chain.node_count || 0}</div>
                        </div>
                    `).join('');
                } else {
                    preview.innerHTML = '<p style="color: var(--text-secondary); padding: 10px;">暂无攻击链</p>';
                }

                // 显示下载按钮
                showDownloadButton('chains');
            } catch (e) {
                console.error('Load chains cache error:', e);
            }
        }
    }
}

async function loadAIData(status) {
    // 检查rules步骤是否完成
    if (status.steps_completed?.rules) {
        document.getElementById('aiInputEmpty').style.display = 'none';
        document.getElementById('aiInputFilled').style.display = 'block';
        document.getElementById('aiActionSection').style.display = 'block';

        // 获取rules数据作为输入
        try {
            const rulesCache = await apiRequest('/api/cache/rules');
            const summary = rulesCache.summary || {};

            document.getElementById('aiInAlerts').textContent = summary.total || summary.total_alerts || 0;
            document.getElementById('aiInHighAlerts').textContent = summary.high || summary.critical || 0;
        } catch (e) {
            document.getElementById('aiInAlerts').textContent = '-';
            document.getElementById('aiInHighAlerts').textContent = '-';
        }

        // 更新模式显示
        try {
            const llmStatus = await apiRequest('/api/llm/status');
            const modeBadge = document.getElementById('aiModeBadge');
            modeBadge.textContent = llmStatus.mock_mode ? '模拟模式' : '真实 AI 模式';
            modeBadge.className = 'ai-mode-badge ' + (llmStatus.mock_mode ? 'mock' : 'real');
        } catch (e) {
            document.getElementById('aiModeBadge').textContent = '未知模式';
        }

        // 检查是否有AI分析结果
        try {
            const aiResult = await apiRequest('/api/llm/result');
            if (!aiResult.error && aiResult.analyzed !== false) {
                displayAIResults(aiResult);
                document.getElementById('aiActionArea').style.display = 'none';
                document.getElementById('aiResultsSection').style.display = 'block';
            }
        } catch (e) {
            // 没有结果，保持显示分析按钮
        }
    }
}

async function loadFullAlertsStats() {
    // 获取完整的告警统计
    const alertsData = await apiRequest('/api/alerts?limit=10000');
    const stats = {
        by_severity: { high: 0, medium: 0, low: 0 },
        total: alertsData.total
    };
    alertsData.alerts.forEach(a => {
        const severity = a.rule?.severity || 'low';
        stats.by_severity[severity] = (stats.by_severity[severity] || 0) + 1;
    });
    return stats;
}

// ==================== 显示/隐藏辅助函数 ====================

function showInputEmpty(pageId, depPage) {
    const depNames = {
        'upload': '数据准备',
        'extract': '事件提取',
        'graph': '关系图构建',
        'rules': '规则检测',
        'threat': '威胁检测',
        'relations': '关系挖掘'
    };
    const emptyDiv = document.getElementById(`${pageId}InputEmpty`);
    emptyDiv.innerHTML = `<p>暂无数据，请先完成 <a href="#page-${depPage}" onclick="navigateTo('${depPage}')">${depNames[depPage]}</a></p>`;
    emptyDiv.style.display = 'block';
    document.getElementById(`${pageId}InputFilled`).style.display = 'none';

    // 禁用按钮
    const btn = document.getElementById(`btn${pageId.charAt(0).toUpperCase() + pageId.slice(1)}`);
    if (btn) btn.disabled = true;
}

function hideInputEmpty(pageId) {
    document.getElementById(`${pageId}InputEmpty`).style.display = 'none';
    document.getElementById(`${pageId}InputFilled`).style.display = 'block';

    // 启用按钮
    const btn = document.getElementById(`btn${pageId.charAt(0).toUpperCase() + pageId.slice(1)}`);
    if (btn) btn.disabled = false;
}

function showOutputSection(pageId) {
    // upload页面使用不同的ID
    const sectionId = pageId === 'upload' ? 'uploadResultSection' : `${pageId}OutputSection`;
    const section = document.getElementById(sectionId);
    if (section) {
        section.style.display = 'block';
    }
}

function showDownloadButton(pageId) {
    // 每个页面对应的下载按钮ID
    const downloadButtonMap = {
        'upload': 'downloadLogs',
        'extract': 'downloadEvents',
        'graph': 'downloadGraph',
        'rules': 'downloadAlerts',
        'threat': 'downloadThreat',
        'relations': 'downloadRelations',
        'chains': 'downloadChains'
    };

    const buttonId = downloadButtonMap[pageId];
    if (buttonId) {
        const button = document.getElementById(buttonId);
        if (button) {
            button.style.display = 'inline-flex';
        }
    }
}

// ==================== 执行步骤 ====================

async function executeStep(pageId, apiEndpoint) {
    try {
        showProcessSection(pageId);
        updateProgress(pageId, 5, '开始执行...');

        const data = await apiRequest(apiEndpoint, { method: 'POST' });

        updateProgress(pageId, 100, '完成');
        markProcessSteps(pageId, true);

        // 短暂延迟后刷新数据
        setTimeout(async () => {
            hideProcessSection(pageId);
            showOutputSection(pageId);
            await loadPageData(pageId);
            updateNavigationStatus();
        }, 500);

    } catch (error) {
        hideProcessSection(pageId);
        alert(`执行失败: ${error.message}`);
    }
}

function showProcessSection(pageId) {
    document.getElementById(`${pageId}ProcessSection`).style.display = 'block';

    // 只有非 upload 页面才有对应的执行按钮
    if (pageId !== 'upload') {
        const btn = document.getElementById(`btn${pageId.charAt(0).toUpperCase() + pageId.slice(1)}`);
        if (btn) btn.disabled = true;
    }
}

function hideProcessSection(pageId) {
    document.getElementById(`${pageId}ProcessSection`).style.display = 'none';
}

function updateProgress(pageId, progress, message) {
    const fillDiv = document.getElementById(`${pageId}ProcessFill`);
    const textDiv = document.getElementById(`${pageId}ProcessText`);

    fillDiv.style.width = `${progress}%`;
    textDiv.textContent = `${progress}% ${message}`;

    // 更新步骤点
    const stepIndex = Math.floor(progress / 25);
    markProcessSteps(pageId, stepIndex);
}

function markProcessSteps(pageId, activeStep) {
    const section = document.getElementById(`${pageId}ProcessSection`);
    const steps = section.querySelectorAll('.process-step');

    steps.forEach((step, index) => {
        const dot = step.querySelector('.step-dot');
        dot.classList.remove('active', 'completed');

        if (index < activeStep) {
            dot.classList.add('completed');
            dot.textContent = '✓';
        } else if (index === activeStep) {
            step.classList.add('active');
        }
    });
}

async function updateNavigationStatus() {
    const status = await apiRequest('/api/status');

    // 转换 steps_status 格式到 steps_completed 格式
    const stepsCompleted = {};
    if (status.steps_status) {
        for (const [stepId, stepInfo] of Object.entries(status.steps_status)) {
            stepsCompleted[stepId] = stepInfo.completed;
        }
    }

    PAGES.forEach(pageId => {
        const navStatus = document.getElementById(`navStatus${pageId.charAt(0).toUpperCase() + pageId.slice(1)}`);
        if (navStatus) {
            if (stepsCompleted[pageId]) {
                navStatus.classList.add('completed');
            } else {
                navStatus.classList.remove('completed');
            }
        }
    });

    // 更新顶部统计
    try {
        const eventsData = await apiRequest('/api/events?limit=1');
        document.getElementById('statTotalEvents').textContent = eventsData.total || '-';

        if (stepsCompleted['rules']) {
            const alertsData = await apiRequest('/api/alerts?limit=1');
            document.getElementById('statAlerts').textContent = alertsData.total || '-';
        }

        if (stepsCompleted['threat']) {
            const threatData = await apiRequest('/api/threat');
            const levelMap = { 'critical': '严重', 'high': '高危', 'medium': '中危', 'low': '低危' };
            document.getElementById('statThreatLevel').textContent = levelMap[threatData.summary?.overall_threat_level] || '-';
        }
    } catch (e) {
        // 忽略错误
    }
}

// ==================== 迷你图渲染 ====================

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

function renderMiniGraph(graphData) {
    const container = document.getElementById('graphMiniContainer');
    if (!container || container.clientWidth === 0) return;

    if (!graphData.nodes || graphData.nodes.length === 0) {
        container.innerHTML = '<p style="text-align:center; padding:50px; color:#999;">暂无数据</p>';
        return;
    }

    // 显示节点类型统计
    displayNodeTypeStats(graphData);

    if (!graphChart) {
        graphChart = echarts.init(container);
    }

    // 关系图构建阶段渲染容量：最多 150 节点 / 300 边
    const MAX_NODES = 150;
    const MAX_EDGES = 300;

    const displayNodes = graphData.nodes.slice(0, MAX_NODES);
    const displayLinks = graphData.edges.slice(0, MAX_EDGES);

    // 计算边权重，用于设置边的粗细
    const maxWeight = Math.max(...displayLinks.map(e => e.weight || 1), 1);

    const nodes = displayNodes.map(node => {
        const nodeType = node.type || 'unknown';
        const baseColor = NODE_TYPE_COLORS[nodeType] || NODE_TYPE_COLORS.unknown;

        // 节点大小基于度数（连接数），度数越大节点越大
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
                    // 显示节点名称的前15个字符
                    const name = params.data.name;
                    return name.length > 15 ? name.substring(0, 12) + '...' : name;
                },
                fontSize: 10,
                color: '#333'
            },
            // 用于tooltip的自定义数据
            data: {
                type: nodeType,
                degree: node.degree,
                name: node.name || node.id
            }
        };
    });

    const links = displayLinks.map(edge => {
        // 边的粗细基于权重
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

    // 窗口调整
    window.addEventListener('resize', () => graphChart && graphChart.resize());
}

// 显示节点类型统计
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
    document.getElementById('processCount').textContent = stats.process;
    document.getElementById('fileCount').textContent = stats.file;
    document.getElementById('socketCount').textContent = stats.socket;
    document.getElementById('unknownCount').textContent = stats.unknown;

    // 显示统计区域
    document.getElementById('nodeTypesStats').style.display = 'flex';
}

// ==================== 上传文件 ====================

let selectedFiles = [];

document.getElementById('fileUpload').addEventListener('change', (e) => {
    selectedFiles = Array.from(e.target.files);

    if (selectedFiles.length === 0) {
        document.getElementById('uploadFileList').style.display = 'none';
        document.getElementById('uploadEmpty').style.display = 'block';
        return;
    }

    // 隐藏上传区域，显示文件预览
    document.getElementById('uploadEmpty').style.display = 'none';
    document.getElementById('uploadFileList').style.display = 'block';

    // 显示文件列表
    const fileList = document.getElementById('selectedFiles');
    fileList.innerHTML = selectedFiles.map((file, index) => {
        // 自动检测文件类型
        const logType = detectLogType(file.name);
        return `
            <div class="file-item">
                <span class="file-item-icon">${getFileIconFromName(file.name)}</span>
                <span class="file-item-name">${escapeHtml(file.name)}</span>
                <span class="file-item-size">${(file.size / 1024).toFixed(1)} KB | ${logType}</span>
                <span class="file-item-remove" onclick="removeFile(${index})">×</span>
            </div>
        `;
    }).join('');
});

// 根据文件名获取图标
function getFileIconFromName(filename) {
    const name = filename.toLowerCase();
    if (name.includes('syslog') || name.includes('process')) return '⚙️';
    if (name.includes('file') || name.includes('audit')) return '📄';
    if (name.includes('netflow') || name.includes('network')) return '🌐';
    if (name.endsWith('.json')) return '📋';
    return '📁';
}

// 移除文件
function removeFile(index) {
    selectedFiles.splice(index, 1);
    if (selectedFiles.length === 0) {
        document.getElementById('uploadFileList').style.display = 'none';
        document.getElementById('uploadEmpty').style.display = 'block';
    } else {
        // 重新渲染文件列表
        const fileList = document.getElementById('selectedFiles');
        fileList.innerHTML = selectedFiles.map((file, i) => {
            const logType = detectLogType(file.name);
            return `
                <div class="file-item">
                    <span class="file-item-icon">${getFileIconFromName(file.name)}</span>
                    <span class="file-item-name">${escapeHtml(file.name)}</span>
                    <span class="file-item-size">${(file.size / 1024).toFixed(1)} KB | ${logType}</span>
                    <span class="file-item-remove" onclick="removeFile(${i})">×</span>
                </div>
            `;
        }).join('');
    }
}

// 清空文件
document.getElementById('btnClearFiles').addEventListener('click', () => {
    selectedFiles = [];
    document.getElementById('fileUpload').value = '';
    document.getElementById('uploadFileList').style.display = 'none';
    document.getElementById('uploadEmpty').style.display = 'block';
});

// 检测日志类型
function detectLogType(filename) {
    const name = filename.toLowerCase();
    if (name.includes('syslog') || name.includes('process')) return '进程日志';
    if (name.includes('file') || name.includes('audit')) return '文件日志';
    if (name.includes('netflow') || name.includes('network')) return '网络日志';
    if (name.endsWith('.json')) return 'JSON格式';
    return '未知类型';
}

// 上传选中的文件
document.getElementById('btnUploadSelected').addEventListener('click', async () => {
    if (selectedFiles.length === 0) {
        alert('请先选择文件');
        return;
    }

    try {
        showProcessSection('upload');
        updateProgress('upload', 10, '上传中...');

        const formData = new FormData();
        selectedFiles.forEach(file => {
            formData.append('files', file);
        });

        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || '上传失败');
        }

        updateProgress('upload', 100, '上传完成');
        setTimeout(async () => {
            hideProcessSection('upload');
            await loadPageData('upload');
            updateNavigationStatus();
        }, 500);

    } catch (error) {
        hideProcessSection('upload');
        alert(`上传失败: ${error.message}`);
    }
});

// ==================== 各步骤按钮事件 ====================

document.getElementById('btnExtract').addEventListener('click', () => {
    executeStep('extract', '/api/step/extract');
});

document.getElementById('btnGraph').addEventListener('click', () => {
    executeStep('graph', '/api/step/graph');
});

document.getElementById('btnRules').addEventListener('click', () => {
    executeStep('rules', '/api/step/rules');
});

document.getElementById('btnThreat').addEventListener('click', () => {
    executeStep('threat', '/api/step/threat');
});

document.getElementById('btnRelations').addEventListener('click', () => {
    executeStep('relations', '/api/step/relations');
});

document.getElementById('btnChains').addEventListener('click', () => {
    executeStep('chains', '/api/step/chains');
});

// ==================== 重置系统 ====================

async function resetSystem() {
    if (!confirm('确定要重置系统吗？所有数据将被清除。')) return;

    try {
        await apiRequest('/api/reset', { method: 'POST' });
        location.reload();
    } catch (error) {
        alert(`重置失败: ${error.message}`);
    }
}

document.getElementById('btnReset').addEventListener('click', resetSystem);

// ==================== 导航点击事件 ====================

document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        const pageId = item.dataset.page;
        navigateTo(pageId);
    });
});

// ==================== 弹窗关闭 ====================

document.querySelector('.modal-close').addEventListener('click', () => {
    document.getElementById('nodeDetailModal').classList.remove('active');
});

document.getElementById('nodeDetailModal').addEventListener('click', (e) => {
    if (e.target.id === 'nodeDetailModal') {
        document.getElementById('nodeDetailModal').classList.remove('active');
    }
});

// ==================== 初始化 ====================

document.addEventListener('DOMContentLoaded', () => {
    // 启动状态轮询
    pollStatus();
    setInterval(pollStatus, 2000);

    // 根据URL hash导航到对应页面
    const hash = window.location.hash.slice(1);
    if (hash && hash.startsWith('page-')) {
        navigateTo(hash.replace('page-', ''));
    }

    // 监听 hash 变化
    window.addEventListener('hashchange', () => {
        const hash = window.location.hash.slice(1);
        if (hash && hash.startsWith('page-')) {
            navigateTo(hash.replace('page-', ''));
        }
    });
});

async function pollStatus() {
    try {
        const status = await apiRequest('/api/status');

        // 更新系统状态文本
        const statusText = {
            'idle': '就绪',
            'running': '运行中'
        };
        document.getElementById('systemStatus').textContent = `系统状态: ${statusText[status.status] || '未知'}`;

    } catch (error) {
        console.error('状态轮询错误:', error);
    }
}


// ==================== AI 分析功能 ====================

// AI 分析按钮事件
document.getElementById('btnAIAnalyze')?.addEventListener('click', async () => {
    await executeAIAnalysis();
});

// 重新分析按钮事件
document.getElementById('btnAIReanalyze')?.addEventListener('click', async () => {
    await executeAIAnalysis();
});

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
        const statusResponse = await apiRequest('/api/llm/status');
        if (!statusResponse.available) {
            updateAIProgress(0, 'LLM 服务不可用');
            alert('LLM 服务不可用，请配置 OPENAI_API_KEY 环境变量');
            document.getElementById('btnAIAnalyze').disabled = false;
            return;
        }

        updateAIProgress(10, '开始 AI 分析...');

        // 执行分析
        const response = await apiRequest('/api/llm/analyze', { method: 'POST' });

        updateAIProgress(100, '分析完成');

        // 显示结果
        displayAIResults(response.result);

        // 隐藏进度，显示结果区域
        setTimeout(() => {
            document.getElementById('aiProgressSection').style.display = 'none';
            document.getElementById('aiResultsSection').style.display = 'block';
            document.getElementById('btnAIAnalyze').disabled = false;
        }, 500);

    } catch (error) {
        document.getElementById('aiProgressSection').style.display = 'none';
        document.getElementById('aiActionArea').style.display = 'block';
        document.getElementById('btnAIAnalyze').disabled = false;
        alert(`AI 分析失败: ${error.message}`);
    }
}

function updateAIProgress(value, message) {
    const fillDiv = document.getElementById('aiProcessFill');
    const textDiv = document.getElementById('aiProcessText');
    const msgDiv = document.getElementById('aiProcessMessage');

    fillDiv.style.width = `${value}%`;
    textDiv.textContent = `${value}%`;
    msgDiv.textContent = message;
}

function displayAIResults(result) {
    // 显示时间戳
    document.getElementById('aiTimestamp').textContent = formatTimestamp(result.analyzed_at);

    // 显示统计数据
    document.getElementById('aiOriginalCount').textContent = result.original_alerts_count || 0;
    document.getElementById('aiFilteredCount').textContent = result.filtered_alerts_count || 0;

    // 显示威胁等级
    const story = result.attack_story || {};
    const threatLevel = story.threat_level || 'unknown';
    const threatLevelDiv = document.getElementById('aiThreatLevel');

    threatLevelDiv.className = 'ai-threat-level ' + threatLevel;
    document.getElementById('aiThreatIcon').textContent = getThreatIcon(threatLevel);
    document.getElementById('aiThreatText').textContent = getThreatLabel(threatLevel);

    // 显示摘要
    document.getElementById('aiSummary').textContent = story.summary || '';

    // 显示攻击阶段统计
    const stages = story.attack_stages || [];
    document.getElementById('aiStagesCount').textContent = stages.length;

    // 显示 IOC 统计
    const iocs = story.ioc_list || [];
    document.getElementById('aiIocCount').textContent = iocs.length;

    // 显示攻击叙述
    const narrative = story.attack_narrative || '';
    document.getElementById('aiNarrative').innerHTML = narrative.replace(/\n/g, '<br>');

    // 显示攻击阶段
    const stagesDiv = document.getElementById('aiStages');
    if (stages.length > 0) {
        stagesDiv.innerHTML = stages.map((stage, i) => `
            <div class="ai-stage-item">
                <div class="ai-stage-number">${i + 1}</div>
                <div class="ai-stage-content">
                    <div class="ai-stage-title">${escapeHtml(stage.stage)}</div>
                    <div class="ai-stage-desc">${escapeHtml(stage.description)}</div>
                </div>
            </div>
        `).join('');
    } else {
        stagesDiv.innerHTML = '<p style="color: var(--text-secondary);">暂无攻击阶段信息</p>';
    }

    // 显示关键发现
    const findingsList = document.getElementById('aiFindings');
    const findings = story.key_findings || [];
    if (findings.length > 0) {
        findingsList.innerHTML = findings.map(f => `<li>${escapeHtml(f)}</li>`).join('');
    } else {
        findingsList.innerHTML = '<li>无特殊发现</li>';
    }

    // 显示 IOC
    const iocList = document.getElementById('aiIocList');
    if (iocs.length > 0) {
        iocList.innerHTML = iocs.map(ioc => `
            <div class="ai-ioc-item">
                <span class="ai-ioc-type">${escapeHtml(ioc.type)}:</span>
                <span class="ai-ioc-value">${escapeHtml(ioc.value)}</span>
            </div>
        `).join('');
    } else {
        iocList.innerHTML = '<p style="color: var(--text-secondary);">未发现 IOC 指标</p>';
    }

    // 显示处置建议
    const recommendationsList = document.getElementById('aiRecommendations');
    const recommendations = result.recommendations || story.recommendations || [];
    if (recommendations.length > 0) {
        recommendationsList.innerHTML = recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('');
    } else {
        recommendationsList.innerHTML = '<li>暂无建议</li>';
    }

    // 隐藏分析按钮区域，显示结果
    document.getElementById('aiActionArea').style.display = 'none';
}

function getThreatIcon(level) {
    const icons = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢'
    };
    return icons[level] || '⚪';
}

function getThreatLabel(level) {
    const labels = {
        'critical': '严重威胁',
        'high': '高危威胁',
        'medium': '中危威胁',
        'low': '低危威胁'
    };
    return labels[level] || '未知';
}
