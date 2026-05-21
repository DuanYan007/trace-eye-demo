/**
 * 攻击链重建页面组件
 * 攻击链森林图可视化
 */

// 图表实例
let chainForestChart = null;
let showChainLabels = true;

// 攻击链数据缓存
let chainsDataCache = null;
let selectedChain = null;

// ATT&CK 技术到攻击阶段的映射
const TECHNIQUE_TACTICS = {
    // 初始访问
    'T1190': { tactic: '初始访问', name: 'Exploit Public-Facing Application', color: '#e74c3c' },
    'T1195': { tactic: '初始访问', name: 'Supply Chain Compromise', color: '#e74c3c' },
    'T1566': { tactic: '初始访问', name: 'Phishing', color: '#e74c3c' },

    // 执行
    'T1059': { tactic: '执行', name: 'Command and Scripting Interpreter', color: '#e67e22' },
    'T1204': { tactic: '执行', name: 'User Execution', color: '#e67e22' },
    'T1203': { tactic: '执行', name: 'Exploitation for Client Execution', color: '#e67e22' },

    // 持久化
    'T1547': { tactic: '持久化', name: 'Boot or Logon Autostart Execution', color: '#f39c12' },
    'T1053': { tactic: '持久化', name: 'Scheduled Task/Job', color: '#f39c12' },
    'T1543': { tactic: '持久化', name: 'Create or Modify System Process', color: '#f39c12' },

    // 权限提升
    'T1068': { tactic: '权限提升', name: 'Exploitation for Privilege Escalation', color: '#f1c40f' },
    'T1548': { tactic: '权限提升', name: 'Abuse Elevation Control Mechanism', color: '#f1c40f' },

    // 防御规避
    'T1027': { tactic: '防御规避', name: 'Obfuscated Files or Information', color: '#9b59b6' },
    'T1055': { tactic: '防御规避', name: 'Process Injection', color: '#9b59b6' },
    'T1014': { tactic: '防御规避', name: 'Rootkit', color: '#9b59b6' },
    'T1070': { tactic: '防御规避', name: 'Indicator Removal', color: '#9b59b6' },

    // 凭证访问
    'T1003': { tactic: '凭证访问', name: 'OS Credential Dumping', color: '#3498db' },
    'T1552': { tactic: '凭证访问', name: 'Unsecured Credentials', color: '#3498db' },
    'T1110': { tactic: '凭证访问', name: 'Brute Force', color: '#3498db' },

    // 发现
    'T1018': { tactic: '发现', name: 'Remote System Discovery', color: '#1abc9c' },
    'T1046': { tactic: '发现', name: 'Network Service Scanning', color: '#1abc9c' },
    'T1005': { tactic: '发现', name: 'Data from Local System', color: '#1abc9c' },
    'T1012': { tactic: '发现', name: 'Query Registry', color: '#1abc9c' },

    // 横向移动
    'T1021': { tactic: '横向移动', name: 'Remote Services', color: '#16a085' },
    'T1570': { tactic: '横向移动', name: 'Lateral Tool Transfer', color: '#16a085' },

    // 收集
    'T1074': { tactic: '收集', name: 'Data Staged', color: '#27ae60' },

    // 渗漏
    'T1041': { tactic: '渗漏', name: 'Exfiltration Over C2 Channel', color: '#c0392b' },
    'T1567': { tactic: '渗漏', name: 'Exfiltration Over Web Service', color: '#c0392b' },

    // C2 (命令与控制)
    'T1071': { tactic: '命令与控制', name: 'Application Layer Protocol', color: '#8e44ad' },
    'T1095': { tactic: '命令与控制', name: 'Non-Application Layer Protocol', color: '#8e44ad' },
    'T1043': { tactic: '命令与控制', name: 'Commonly Used Port', color: '#8e44ad' },

    // 影响
    'T1486': { tactic: '影响', name: 'Data Encrypted for Impact', color: '#7f8c8d' },
    'T1496': { tactic: '影响', name: 'Resource Hijacking', color: '#7f8c8d' },

    // 其他
    'T1105': { tactic: '初始访问', name: 'Ingress Tool Transfer', color: '#e74c3c' },
    'T1505': { tactic: '持久化', name: 'Server Software Component', color: '#f39c12' },
    'T1078': { tactic: '初始访问', name: 'Valid Accounts', color: '#e74c3c' },
    'T1222': { tactic: '防御规避', name: 'File Permissions Modification', color: '#9b59b6' },
    'T1557': { tactic: '横向移动', name: 'Adversary-in-the-Middle', color: '#16a085' },
    'T1611': { tactic: '权限提升', name: 'Escape to Host', color: '#f1c40f' },
    'T1048': { tactic: '渗漏', name: 'Exfiltration Over C2', color: '#c0392b' }
};

// 攻击阶段顺序
const TACTIC_ORDER = [
    '初始访问', '执行', '持久化', '权限提升', '防御规避',
    '凭证访问', '发现', '横向移动', '收集', '渗漏',
    '命令与控制', '影响'
];

// 组件加载完成后的初始化
window.addEventListener('componentLoaded', (e) => {
    if (e.detail.name === 'chains') {
        initChainsPage();
    }
});

/**
 * 初始化攻击链重建页面
 */
function initChainsPage() {
    const btn = document.getElementById('btnChains');
    if (btn) {
        btn.addEventListener('click', () => executeStep('chains', '/step/chains'));
    }
}

/**
 * 加载攻击链重建页面数据
 */
async function loadChainsData(status, pageDataCache) {
    if (status.steps_completed?.relations) {
        document.getElementById('chainsInputEmpty').style.display = 'none';
        document.getElementById('chainsInputFilled').style.display = 'block';

        try {
            const relationsData = await DataCache.get('relations');
            const relationsInfo = relationsData?.data || relationsData || {};

            const relationsEl = document.getElementById('chainsInRelations');
            const relationsCount = relationsInfo.statistics?.total_relations ||
                                  relationsInfo.suspicious_relations?.length || 0;
            if (relationsEl) relationsEl.textContent = relationsCount;

            const rulesData = await DataCache.get('rules');
            const rulesInfo = rulesData?.data || rulesData || {};
            let alertsCount = 0;
            if (rulesInfo.alerts?.length) {
                alertsCount = rulesInfo.alerts.length;
            } else if (rulesInfo.alerts_by_rule && typeof rulesInfo.alerts_by_rule === 'object') {
                alertsCount = Object.values(rulesInfo.alerts_by_rule).reduce((sum, arr) => sum + (Array.isArray(arr) ? arr.length : 0), 0);
            }
            const alertsEl = document.getElementById('chainsInAlerts');
            if (alertsEl) alertsEl.textContent = alertsCount;
        } catch (e) {
            console.error('[Chains] Load input data error:', e);
        }

        if (status.steps_completed?.chains) {
            await loadChainsResults(pageDataCache);
        }
    }
}

/**
 * 加载攻击链结果
 */
async function loadChainsResults(pageDataCache) {
    try {
        // 使用缓存数据
        const chainsCache = pageDataCache || await DataCache.get('chains');
        const data = chainsCache?.data || chainsCache || {};
        chainsDataCache = data;

        console.log('[Chains] Loaded data from cache');

        const attackChains = chainsDataCache.attack_chains || [];
        const statistics = chainsDataCache.statistics || {};

        // 更新统计
        document.getElementById('chainsOutTotal').textContent = attackChains.length || statistics.total_chains || 0;

        const totalNodes = attackChains.reduce((sum, chain) => sum + (chain.node_count || 0), 0);
        document.getElementById('chainsOutNodes').textContent = statistics.total_nodes_in_chains || totalNodes;

        const totalAlerts = attackChains.reduce((sum, chain) => sum + (chain.related_alerts?.length || 0), 0);
        document.getElementById('chainsOutAlerts').textContent = totalAlerts;

        const allTechniques = new Set();
        attackChains.forEach(chain => {
            (chain.attack_techniques || []).forEach(t => allTechniques.add(t));
        });
        document.getElementById('chainsOutTechniques').textContent = allTechniques.size;

        // 渲染攻击链森林列表
        renderChainForest(attackChains);

        // 显示下载按钮
        const downloadBtn = document.getElementById('downloadChains');
        if (downloadBtn) {
            downloadBtn.style.display = 'inline-block';
        }

        // 显示输出区域
        document.getElementById('chainsOutputSection').style.display = 'block';

    } catch (e) {
        console.error('[Chains] Load results error:', e);
    }
}

/**
 * 渲染攻击链森林列表
 */
function renderChainForest(attackChains) {
    const container = document.getElementById('chainTreesList');
    if (!container) return;

    document.getElementById('forestChainCount').textContent = attackChains.length;

    if (attackChains.length === 0) {
        container.innerHTML = `
            <p style="text-align:center; color:#999; padding:20px;">
                未检测到攻击链
            </p>
        `;
        return;
    }

    container.innerHTML = attackChains.map((chain, index) => {
        const nodeCount = chain.node_count || chain.nodes?.length || 0;
        const alertCount = chain.related_alerts?.length || 0;
        const techCount = chain.attack_techniques?.length || 0;
        const isSelected = selectedChain && selectedChain.chain_id === chain.chain_id;

        // 获取主要技术类型
        const techniques = chain.attack_techniques || [];
        const tacticCounts = {};
        techniques.forEach(tech => {
            const tacticInfo = TECHNIQUE_TACTICS[tech];
            if (tacticInfo) {
                tacticCounts[tacticInfo.tactic] = (tacticCounts[tacticInfo.tactic] || 0) + 1;
            }
        });

        const mainTactic = Object.entries(tacticCounts)
            .sort((a, b) => b[1] - a[1])[0]?.[0] || '未知';

        return `
            <div class="chain-tree-card ${isSelected ? 'selected' : ''}" onclick="selectAttackChain('${chain.chain_id}')">
                <div class="chain-card-header">
                    <span class="chain-card-index">#${index + 1}</span>
                    <span class="chain-card-type">${escapeHtml(chain.attack_type || '未知攻击')}</span>
                </div>
                <div class="chain-card-title">${escapeHtml(chain.description?.substring(0, 50) || '攻击链')}</div>
                <div class="chain-card-stats">
                    <span class="chain-stat">🔗 ${nodeCount} 节点</span>
                    <span class="chain-stat">⚠️ ${alertCount} 告警</span>
                    <span class="chain-stat">🎯 ${techCount} 技术</span>
                </div>
                <div class="chain-card-tactic">主要阶段: ${escapeHtml(mainTactic)}</div>
            </div>
        `;
    }).join('');
}

/**
 * 选择攻击链并显示详情
 */
async function selectAttackChain(chainId) {
    const chain = chainsDataCache.attack_chains?.find(c => c.chain_id === chainId);
    if (!chain) return;

    selectedChain = chain;

    // 更新选中状态
    renderChainForest(chainsDataCache.attack_chains || []);

    // 更新详情标题
    document.getElementById('chainDetailTitle').textContent = `📋 ${escapeHtml(chain.attack_type || '攻击链详情')}`;

    // 隐藏占位符，显示内容
    document.getElementById('chainDetailPlaceholder').style.display = 'none';
    document.getElementById('chainDetailContent').style.display = 'block';

    // 更新信息卡片
    document.getElementById('detailAttackType').textContent = chain.attack_type || '-';
    document.getElementById('detailNodeCount').textContent = chain.node_count || chain.nodes?.length || 0;
    document.getElementById('detailAlertCount').textContent = chain.related_alerts?.length || 0;
    document.getElementById('detailTechCount').textContent = chain.attack_techniques?.length || 0;

    // 渲染技术标签
    renderTechniqueTags(chain.attack_techniques || []);

    // 渲染关联节点列表
    await renderChainNodes(chain.nodes || []);

    // 渲染攻击链森林图
    await renderChainForestChart(chain);
}

/**
 * 渲染 ATT&CK 技术标签
 */
function renderTechniqueTags(techniques) {
    const container = document.getElementById('techniquesTags');
    if (!container) return;

    if (techniques.length === 0) {
        container.innerHTML = '<p style="color:#999;">无技术标签</p>';
        return;
    }

    // 按攻击阶段分组
    const tacticGroups = {};
    techniques.forEach(tech => {
        const info = TECHNIQUE_TACTICS[tech] || { tactic: '其他', name: tech, color: '#95a5a6' };
        if (!tacticGroups[info.tactic]) {
            tacticGroups[info.tactic] = [];
        }
        tacticGroups[info.tactic].push({ id: tech, ...info });
    });

    container.innerHTML = TACTIC_ORDER.filter(t => tacticGroups[t]).map(tactic => {
        const techs = tacticGroups[tactic];
        const color = techs[0]?.color || '#95a5a6';
        return `
            <div class="tactic-group">
                <span class="tactic-label" style="background:${color}">${escapeHtml(tactic)}</span>
                <div class="technique-list">
                    ${techs.map(t => `
                        <span class="technique-tag" title="${escapeHtml(t.name)}">
                            ${t.id}
                        </span>
                    `).join('')}
                </div>
            </div>
        `;
    }).join('');
}

/**
 * 渲染关联节点列表
 */
async function renderChainNodes(nodeIds) {
    const container = document.getElementById('chainNodesList');
    if (!container) return;

    if (nodeIds.length === 0) {
        container.innerHTML = '<p style="color:#999;">无关联节点</p>';
        return;
    }

    // 获取图数据以获取节点信息
    try {
        const graphCache = await DataCache.get('graph');
        const graphData = graphCache?.data || graphCache || {};
        const nodesMap = {};
        if (graphData.nodes) {
            graphData.nodes.forEach(node => {
                nodesMap[node.id] = node;
            });
        }

        container.innerHTML = nodeIds.slice(0, 20).map(nodeId => {
            const node = nodesMap[nodeId] || { name: nodeId, type: 'unknown' };
            return `
                <span class="chain-node-tag ${node.type}">
                    ${escapeHtml(node.name || nodeId)}
                </span>
            `;
        }).join('');

        if (nodeIds.length > 20) {
            container.innerHTML += `<p style="color:#999; font-size:0.8rem;">...还有 ${nodeIds.length - 20} 个节点</p>`;
        }
    } catch (e) {
        console.error('[Chains] Render nodes error:', e);
    }
}

/**
 * 渲染攻击链森林图
 */
async function renderChainForestChart(chain) {
    const container = document.getElementById('chainForestChart');
    if (!container) return;

    if (container.clientWidth === 0) {
        setTimeout(() => renderChainForestChart(chain), 100);
        return;
    }

    // 初始化图表
    if (chainForestChart) {
        chainForestChart.dispose();
    }
    chainForestChart = echarts.init(container);

    // 获取图数据
    const graphCache = await DataCache.get('graph');
    const graphData = graphCache?.data || graphCache || {};
    const nodesMap = {};
    if (graphData.nodes) {
        graphData.nodes.forEach(node => {
            nodesMap[node.id] = node;
        });
    }

    // 按攻击阶段组织节点
    const techniques = chain.attack_techniques || [];
    const tacticNodes = {};
    const chainNodeIds = chain.nodes || [];

    // 为每个节点分配攻击阶段
    chainNodeIds.forEach(nodeId => {
        const node = nodesMap[nodeId] || { name: nodeId, type: 'unknown' };
        // 简单分配：根据节点类型或索引分配阶段
        const nodeIndex = chainNodeIds.indexOf(nodeId);
        const tacticIndex = Math.min(Math.floor(nodeIndex / Math.max(1, chainNodeIds.length / TACTIC_ORDER.length)), TACTIC_ORDER.length - 1);
        const tactic = TACTIC_ORDER[tacticIndex];

        if (!tacticNodes[tactic]) {
            tacticNodes[tactic] = [];
        }
        tacticNodes[tactic].push({
            id: nodeId,
            name: node.name || nodeId,
            type: node.type,
            value: 10
        });
    });

    // 构建树形数据
    const treeData = {
        name: chain.attack_type || '攻击链',
        children: TACTIC_ORDER.filter(t => tacticNodes[t]).map(tactic => ({
            name: tactic,
            children: tacticNodes[tactic].map(node => ({
                name: node.name,
                value: node.value
            }))
        }))
    };

    const option = {
        backgroundColor: 'transparent',
        tooltip: {
            backgroundColor: 'rgba(8, 18, 38, 0.96)',
            borderColor: 'rgba(125, 178, 255, 0.28)',
            textStyle: { color: '#dbeafe' },
            formatter: function(params) {
                if (params.treePathInfo) {
                    const path = params.treePathInfo.map(p => p.name).join(' → ');
                    return `<strong>${params.name}</strong><br/>路径: ${path}`;
                }
                return params.name;
            }
        },
        series: [{
            type: 'tree',
            data: [treeData],
            top: '10%',
            left: '10%',
            bottom: '10%',
            right: '20%',
            symbolSize: 8,
            label: {
                show: showChainLabels,
                position: 'left',
                verticalAlign: 'middle',
                align: 'right',
                fontSize: 11,
                color: '#dbeafe',
                width: 130,
                overflow: 'truncate',
                textBorderColor: 'rgba(3, 10, 24, 0.9)',
                textBorderWidth: 3
            },
            leaves: {
                label: {
                    show: showChainLabels,
                    position: 'right',
                    verticalAlign: 'middle',
                    align: 'left',
                    color: '#dbeafe',
                    width: 150,
                    overflow: 'truncate',
                    textBorderColor: 'rgba(3, 10, 24, 0.9)',
                    textBorderWidth: 3
                }
            },
            emphasis: {
                focus: 'descendant'
            },
            expandAndCollapse: true,
            animationDuration: 550,
            animationDurationUpdate: 750,
            itemStyle: {
                color: function(params) {
                    const tactic = params.data.name;
                    const tech = techniques.find(t => TECHNIQUE_TACTICS[t]?.tactic === tactic);
                    return tech ? TECHNIQUE_TACTICS[tech]?.color || '#3498db' : '#3498db';
                },
                borderColor: 'rgba(219, 234, 254, 0.74)'
            },
            lineStyle: {
                color: 'rgba(148, 163, 184, 0.38)',
                width: 1.5,
                curveness: 0.5
            }
        }]
    };

    chainForestChart.setOption(option);

    // 窗口调整
    window.addEventListener('resize', () => chainForestChart && chainForestChart.resize());
}

/**
 * 重置视图
 */
function resetChainZoom() {
    if (chainForestChart) {
        chainForestChart.dispatchAction({ type: 'restore' });
    }
}

/**
 * 切换标签显示
 */
function toggleChainLabels() {
    showChainLabels = !showChainLabels;
    if (chainForestChart) {
        chainForestChart.setOption({
            series: [{
                label: {
                    show: showChainLabels,
                    color: '#dbeafe'
                },
                leaves: {
                    label: {
                        show: showChainLabels,
                        color: '#dbeafe'
                    }
                }
            }]
        });
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

/**
 * HTML转义
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// 导出到全局
window.selectAttackChain = selectAttackChain;
window.resetChainZoom = resetChainZoom;
window.toggleChainLabels = toggleChainLabels;

// 覆盖main.js中的占位函数
window.TraceEye = window.TraceEye || {};
window.TraceEye.loadChainsData = loadChainsData;
window.executeStep = executeStep;
