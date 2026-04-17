/**
 * 规则检测页面组件
 * 包含仪表盘、时间线、规则列表三个视图
 */

// 规则检测图表实例
let rulesDistributionChart = null;
let rulesTrendChart = null;
let scatterMatrixChart = null;

// 组件加载完成后的初始化
window.addEventListener('componentLoaded', (e) => {
    if (e.detail.name === 'rules') {
        initRulesPage();
    }
});

/**
 * 初始化规则检测页面
 */
function initRulesPage() {
    // 绑定执行按钮
    const btn = document.getElementById('btnRules');
    if (btn) {
        btn.addEventListener('click', () => executeStep('rules', '/step/rules'));
    }

    // 绑定视图切换事件
    document.querySelectorAll('.view-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            switchRulesView(tab.dataset.view);
        });
    });

    // 绑定导出按钮事件
    document.querySelectorAll('.btn-export').forEach(btn => {
        btn.addEventListener('click', () => {
            const format = btn.getAttribute('onclick')?.match(/exportReport\('(\w+)'\)/)?.[1];
            if (format) exportReport(format);
        });
    });
}

/**
 * 加载规则检测页面数据
 * @param {Object} status - 系统状态
 * @param {Object} pageDataCache - 页面缓存数据
 */
async function loadRulesData(status, pageDataCache) {
    // 检查graph步骤是否完成
    if (status.steps_completed?.graph) {
        document.getElementById('rulesInputEmpty').style.display = 'none';
        document.getElementById('rulesInputFilled').style.display = 'block';

        // 从缓存获取graph步骤的数据作为输入
        try {
            const graphData = await DataCache.get('graph');
            const data = graphData?.data || {};
            const summary = graphData?.summary || {};
            const nodesEl = document.getElementById('rulesInNodes');
            const edgesEl = document.getElementById('rulesInEdges');

            // 优先从 summary 获取，其次从 data 获取，最后计算数组长度
            const nodeCount = summary.node_count || summary.nodes || data.node_count || data.nodes?.length || 0;
            const edgeCount = summary.edge_count || summary.edges || data.edge_count || data.edges?.length || 0;

            if (nodesEl) nodesEl.textContent = nodeCount || '-';
            if (edgesEl) edgesEl.textContent = edgeCount || '-';
        } catch (e) {
            const nodesEl = document.getElementById('rulesInNodes');
            const edgesEl = document.getElementById('rulesInEdges');
            if (nodesEl) nodesEl.textContent = '-';
            if (edgesEl) edgesEl.textContent = '-';
        }

        // 显示输出统计（如果rules已完成）
        if (status.steps_completed?.rules) {
            const outputSection = document.getElementById('rulesOutputSection');
            if (outputSection) {
                outputSection.style.display = 'block';
            }

            try {
                const rulesData = pageDataCache || await DataCache.get('rules');
                const data = rulesData?.data || {};
                const summary = rulesData?.summary || {};

                const bySeverity = summary.by_severity || data.by_severity || {};

                const highEl = document.getElementById('rulesOutHigh');
                const mediumEl = document.getElementById('rulesOutMedium');
                const lowEl = document.getElementById('rulesOutLow');

                if (highEl) highEl.textContent = bySeverity.high || 0;
                if (mediumEl) mediumEl.textContent = bySeverity.medium || 0;
                if (lowEl) lowEl.textContent = bySeverity.low || 0;

                // 显示下载按钮
                const downloadBtn = document.getElementById('downloadAlerts');
                if (downloadBtn) {
                    downloadBtn.style.display = 'inline-block';
                }

                // 加载增强视图数据
                await loadRulesViewData(rulesData);
            } catch (e) {
                console.error('Load rules data error:', e);
            }
        }
    }
}

/**
 * 切换规则检测视图
 */
function switchRulesView(viewName) {
    rulesState.currentView = viewName;

    // 更新标签样式
    document.querySelectorAll('.view-tab').forEach(tab => {
        tab.classList.remove('active');
        if (tab.dataset.view === viewName) {
            tab.classList.add('active');
        }
    });

    // 显示对应视图
    document.querySelectorAll('.rules-view-container').forEach(view => {
        view.style.display = 'none';
    });
    const targetView = document.getElementById(`view-${viewName}`);
    if (targetView) {
        targetView.style.display = 'block';
    }

    // 加载视图数据
    loadRulesViewData();
}

/**
 * 加载规则检测视图数据
 * @param {Object} rulesData - 规则数据缓存
 */
async function loadRulesViewData(rulesData) {
    try {
        // 从缓存获取告警数据
        const rulesCache = await DataCache.get('rules');
        const cacheData = rulesCache?.data || rulesCache || {};
        const allAlerts = cacheData.alerts || [];

        // 处理数据
        rulesState.data.alerts = allAlerts;
        rulesState.data.alertsByRule = {};
        rulesState.data.alertsByTime = {};

        // 按规则统计
        allAlerts.forEach(alert => {
            const ruleId = alert.rule?.rule_id || 'unknown';
            if (!rulesState.data.alertsByRule[ruleId]) {
                rulesState.data.alertsByRule[ruleId] = [];
            }
            rulesState.data.alertsByRule[ruleId].push(alert);

            // 按时间统计 (按小时)
            const hour = alert.timestamp ? alert.timestamp.substring(0, 13) : 'unknown';
            if (!rulesState.data.alertsByTime[hour]) {
                rulesState.data.alertsByTime[hour] = 0;
            }
            rulesState.data.alertsByTime[hour]++;
        });

        // 根据当前视图渲染
        switch (rulesState.currentView) {
            case 'dashboard':
                renderDashboardView();
                break;
            case 'timeline':
                renderTimelineView();
                break;
            case 'list':
                renderRulesListView();
                break;
        }

    } catch (error) {
        console.error('加载规则视图数据失败:', error);
    }
}

/**
 * 渲染仪表盘视图
 */
function renderDashboardView() {
    console.log('[Rules] renderDashboardView, total alerts:', rulesState.data.alerts.length);

    // 更新统计卡片
    const totalAlerts = rulesState.data.alerts.length;
    const highAlerts = rulesState.data.alerts.filter(a => a.rule?.severity === 'high').length;
    const mediumAlerts = rulesState.data.alerts.filter(a => a.rule?.severity === 'medium').length;
    const lowAlerts = rulesState.data.alerts.filter(a => a.rule?.severity === 'low').length;

    console.log('[Rules] Severity counts - high:', highAlerts, 'medium:', mediumAlerts, 'low:', lowAlerts);

    const highEl = document.getElementById('rulesOutHigh');
    const mediumEl = document.getElementById('rulesOutMedium');
    const lowEl = document.getElementById('rulesOutLow');

    if (highEl) highEl.textContent = highAlerts;
    if (mediumEl) mediumEl.textContent = mediumAlerts;
    if (lowEl) lowEl.textContent = lowAlerts;

    // 渲染规则分布图表
    renderRulesDistributionChart();

    // 渲染趋势图表
    renderRulesTrendChart();

    // 渲染规则分类卡片
    renderRuleCategories();
}

/**
 * 渲染规则分布图表
 */
function renderRulesDistributionChart() {
    const chartDom = document.getElementById('rulesDistributionChart');
    if (!chartDom) return;

    if (rulesDistributionChart) {
        rulesDistributionChart.dispose();
    }

    // 按严重程度统计
    const severityData = {
        high: rulesState.data.alerts.filter(a => a.rule?.severity === 'high').length,
        medium: rulesState.data.alerts.filter(a => a.rule?.severity === 'medium').length,
        low: rulesState.data.alerts.filter(a => a.rule?.severity === 'low').length
    };

    rulesDistributionChart = echarts.init(chartDom);
    const option = {
        title: {
            text: '告警严重程度分布',
            left: 'center',
            textStyle: { color: '#bdc3c7', fontSize: 14 }
        },
        tooltip: {
            trigger: 'item',
            formatter: '{b}: {c} ({d}%)'
        },
        legend: {
            orient: 'vertical',
            left: 'left',
            textStyle: { color: '#bdc3c7' }
        },
        series: [{
            type: 'pie',
            radius: ['40%', '70%'],
            avoidLabelOverlap: false,
            itemStyle: {
                borderRadius: 10,
                borderColor: '#1e1e1e',
                borderWidth: 2
            },
            label: {
                show: true,
                color: '#bdc3c7'
            },
            data: [
                { value: severityData.high, name: '高危', itemStyle: { color: '#e74c3c' } },
                { value: severityData.medium, name: '中危', itemStyle: { color: '#f39c12' } },
                { value: severityData.low, name: '低危', itemStyle: { color: '#27ae60' } }
            ]
        }]
    };
    rulesDistributionChart.setOption(option);
}

/**
 * 渲染规则趋势图表
 */
function renderRulesTrendChart() {
    const chartDom = document.getElementById('rulesTrendChart');
    if (!chartDom) return;

    if (rulesTrendChart) {
        rulesTrendChart.dispose();
    }

    // 按时间排序
    const sortedTimes = Object.keys(rulesState.data.alertsByTime).sort();
    const timeData = sortedTimes.map(t => rulesState.data.alertsByTime[t]);

    rulesTrendChart = echarts.init(chartDom);
    const option = {
        title: {
            text: '告警时间趋势',
            left: 'center',
            textStyle: { color: '#bdc3c7', fontSize: 14 }
        },
        tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'shadow' }
        },
        xAxis: {
            type: 'category',
            data: sortedTimes,
            axisLabel: { color: '#bdc3c7', rotate: 45 },
            axisLine: { lineStyle: { color: '#3d3d3d' } }
        },
        yAxis: {
            type: 'value',
            axisLabel: { color: '#bdc3c7' },
            axisLine: { lineStyle: { color: '#3d3d3d' } },
            splitLine: { lineStyle: { color: '#2d2d2d' } }
        },
        series: [{
            data: timeData,
            type: 'bar',
            itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                    { offset: 0, color: '#3498db' },
                    { offset: 1, color: '#2980b9' }
                ]),
                borderRadius: [4, 4, 0, 0]
            }
        }]
    };
    rulesTrendChart.setOption(option);
}

/**
 * 渲染规则分类卡片
 */
function renderRuleCategories() {
    const container = document.getElementById('ruleCategoriesGrid');
    if (!container) return;

    let html = '';
    for (const [key, category] of Object.entries(RULE_CATEGORIES)) {
        // 统计该分类的告警数
        let count = 0;
        category.rules.forEach(ruleId => {
            count += rulesState.data.alertsByRule[ruleId]?.length || 0;
        });

        // 触发该分类的规则数
        const triggeredRules = category.rules.filter(ruleId =>
            rulesState.data.alertsByRule[ruleId]?.length > 0
        ).length;

        html += `
            <div class="rule-category-card" onclick="filterByCategory('${key}')" style="cursor: pointer;">
                <div class="category-icon" style="background: ${category.color}20; color: ${category.color};">
                    <i class="fas ${category.icon}"></i>
                </div>
                <div class="category-info">
                    <div class="category-name">${category.name}</div>
                    <div class="category-stats">
                        <span class="stat-item">
                            <strong>${count}</strong> 告警
                        </span>
                        <span class="stat-item">
                            <strong>${triggeredRules}</strong> / ${category.rules.length} 规则
                        </span>
                    </div>
                </div>
                <div class="category-arrow">
                    <i class="fas fa-arrow-right"></i>
                </div>
            </div>
        `;
    }
    container.innerHTML = html;
}

/**
 * 渲染时间线视图 - 散点时间矩阵
 */
function renderTimelineView() {
    const container = document.getElementById('scatterMatrixChart');
    if (!container) return;

    if (rulesState.data.alerts.length === 0) {
        container.innerHTML = '<p style="text-align:center; padding:50px; color:#999;">暂无告警数据</p>';
        return;
    }

    // 按时间排序
    let sortedAlerts = [...rulesState.data.alerts].sort((a, b) =>
        new Date(a.timestamp) - new Date(b.timestamp)
    );

    // 应用过滤器
    if (rulesState.filter.severity) {
        sortedAlerts = sortedAlerts.filter(a => a.rule?.severity === rulesState.filter.severity);
    }
    if (rulesState.filter.category) {
        const categoryRules = RULE_CATEGORIES[rulesState.filter.category].rules;
        sortedAlerts = sortedAlerts.filter(a =>
            categoryRules.includes(a.rule?.rule_id)
        );
    }

    if (sortedAlerts.length === 0) {
        container.innerHTML = '<p style="text-align:center; padding:50px; color:#999;">没有符合条件的告警</p>';
        return;
    }

    // 计算时间范围
    const startTime = new Date(sortedAlerts[0].timestamp).getTime();
    const endTime = new Date(sortedAlerts[sortedAlerts.length - 1].timestamp).getTime();
    const timeSpan = endTime - startTime || 1;

    // 更新统计
    const totalAlertsEl = document.getElementById('timelineTotalAlerts');
    const timeSpanEl = document.getElementById('timelineTimeSpan');
    if (totalAlertsEl) totalAlertsEl.textContent = sortedAlerts.length;
    if (timeSpanEl) {
        const hours = Math.floor(timeSpan / 3600000);
        const minutes = Math.floor((timeSpan % 3600000) / 60000);
        timeSpanEl.textContent = hours > 0 ? `${hours}小时${minutes}分钟` : `${minutes}分钟`;
    }

    // 渲染散点时间矩阵
    renderScatterMatrix(sortedAlerts, startTime, endTime);
}

/**
 * 渲染散点时间矩阵
 */
function renderScatterMatrix(alerts, startTime, endTime) {
    const container = document.getElementById('scatterMatrixChart');
    if (!container) return;

    // 初始化图表
    if (scatterMatrixChart) {
        scatterMatrixChart.dispose();
    }
    scatterMatrixChart = echarts.init(container);

    // 准备数据 - 按类别分组
    const categoryOrder = ['file', 'process', 'network', 'sequence', 'temporal'];
    const categoryNames = {
        'file': '📄 文件',
        'process': '⚙️ 进程',
        'network': '🌐 网络',
        'sequence': '📋 序列',
        'temporal': '🕐 时序'
    };

    // 构建散点数据
    const scatterData = [];
    alerts.forEach((alert, index) => {
        const category = alert.rule?.category || 'unknown';
        const severity = alert.rule?.severity || 'low';
        const ruleInfo = RULE_DEFINITIONS[alert.rule?.rule_id] || {};

        const categoryIndex = categoryOrder.indexOf(category);
        if (categoryIndex === -1) return;

        const alertTime = new Date(alert.timestamp).getTime();
        const timePercent = (alertTime - startTime) / (endTime - startTime);

        // 散点大小根据严重程度
        const sizeMap = { high: 20, medium: 14, low: 8 };
        const symbolSize = sizeMap[severity] || 8;

        scatterData.push({
            name: alert.rule?.rule_id || 'unknown',
            value: [timePercent * 100, categoryIndex, alert],
            severity: severity,
            category: category,
            symbolSize: symbolSize,
            itemStyle: {
                color: severity === 'high' ? '#e74c3c' :
                       severity === 'medium' ? '#f39c12' : '#27ae60',
                opacity: 0.8,
                shadowBlur: severity === 'high' ? 15 : 8,
                shadowColor: severity === 'high' ? 'rgba(231, 76, 60, 0.6)' :
                             severity === 'medium' ? 'rgba(243, 156, 18, 0.4)' :
                             'rgba(39, 174, 96, 0.3)'
            }
        });
    });

    // Y轴刻度
    const yAxisData = categoryOrder.map(cat => categoryNames[cat]);

    // 更新Y轴标签 - 使用中文类别名称
    const yAxisLabelsEl = document.getElementById('matrixYAxisLabels');
    if (yAxisLabelsEl) {
        const chineseNames = {
            'file': '📄 文件异常',
            'process': '⚙️ 进程异常',
            'network': '🌐 网络异常',
            'sequence': '📋 行为序列',
            'temporal': '🕐 时序异常'
        };
        yAxisLabelsEl.innerHTML = categoryOrder.map(cat => {
            return `<div class="y-axis-label">${chineseNames[cat]}</div>`;
        }).join('');
    }

    // 更新X轴标签（实际时间刻度）
    const xAxisLabelsEl = document.getElementById('matrixXAxisLabels');
    if (xAxisLabelsEl) {
        const formatTime = (timestamp) => {
            const date = new Date(timestamp);
            return date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
        };
        const timePoints = [0, 0.25, 0.5, 0.75, 1];
        const timeLabels = timePoints.map(p => {
            const time = startTime + (endTime - startTime) * p;
            return formatTime(time);
        });
        xAxisLabelsEl.innerHTML = timeLabels.map(label =>
            `<div class="x-axis-label">${label}</div>`
        ).join('');
    }

    const option = {
        grid: {
            left: '10%',
            right: '5%',
            top: '10%',
            bottom: '15%'
        },
        tooltip: {
            formatter: function(params) {
                const alert = params.data.value[2];
                const time = new Date(alert.timestamp).toLocaleString('zh-CN');
                return `
                    <div style="padding:8px;">
                        <div style="font-weight:600;margin-bottom:6px;">${alert.rule?.rule_id || '未知'}</div>
                        <div style="font-size:12px;color:#666;">${alert.rule?.rule_name || ''}</div>
                        <div style="margin-top:6px;font-size:12px;">
                            <span style="color:${params.color}">●</span> ${alert.rule?.severity || 'low'}
                        </div>
                        <div style="font-size:12px;color:#888;margin-top:4px;">${time}</div>
                    </div>
                `;
            }
        },
        xAxis: {
            type: 'value',
            min: 0,
            max: 100,
            axisLine: { show: false },
            axisTick: { show: false },
            axisLabel: { show: false },
            splitLine: {
                show: true,
                lineStyle: { color: '#f0f0f0', type: 'dashed' }
            }
        },
        yAxis: {
            type: 'category',
            data: categoryOrder.map((cat, i) => ({
                value: i,
                name: categoryNames[cat]
            })),
            axisLine: { show: false },
            axisTick: { show: false },
            axisLabel: { show: false },
            splitLine: { show: false }
        },
        series: [{
            type: 'scatter',
            data: scatterData,
            symbol: 'circle',
            hoverAnimation: {
                scale: 1.5,
                duration: 300
            },
            markLine: {
                silent: true,
                lineStyle: {
                    color: '#e0e0e0',
                    type: 'solid'
                },
                data: categoryOrder.map((cat, i) => [
                    { coord: [0, i] },
                    { coord: [100, i] }
                ])
            }
        }]
    };

    scatterMatrixChart.setOption(option);

    // 绑定点击事件
    scatterMatrixChart.off('click');
    scatterMatrixChart.on('click', function(params) {
        if (params.data && params.data.value) {
            showScatterDetail(params.data.value[2]);
        }
    });

    // 窗口调整
    window.addEventListener('resize', () => scatterMatrixChart && scatterMatrixChart.resize());
}

/**
 * 显示散点详情面板
 */
function showScatterDetail(alert) {
    const panel = document.getElementById('scatterDetailPanel');
    const content = document.getElementById('scatterDetailContent');

    if (!panel || !content) return;

    const severity = alert.rule?.severity || 'low';
    const ruleInfo = RULE_DEFINITIONS[alert.rule?.rule_id] || {};
    const categoryInfo = RULE_CATEGORIES[ruleInfo.category] || { name: '未知' };

    const severityLabels = {
        high: '高危',
        medium: '中危',
        low: '低危'
    };

    content.innerHTML = `
        <div class="detail-section">
            <div class="detail-section-title">基本信息</div>
            <div class="detail-item">
                <span class="detail-item-label">规则ID</span>
                <span class="detail-item-value">${alert.rule?.rule_id || '-'}</span>
            </div>
            <div class="detail-item">
                <span class="detail-item-label">规则名称</span>
                <span class="detail-item-value">${ruleInfo.name || alert.rule?.rule_name || '-'}</span>
            </div>
            <div class="detail-item">
                <span class="detail-item-label">严重程度</span>
                <span class="detail-item-value"><span class="detail-badge ${severity}">${severityLabels[severity]}</span></span>
            </div>
            <div class="detail-item">
                <span class="detail-item-label">类别</span>
                <span class="detail-item-value">${categoryInfo.name}</span>
            </div>
            <div class="detail-item">
                <span class="detail-item-label">时间</span>
                <span class="detail-item-value">${new Date(alert.timestamp).toLocaleString('zh-CN')}</span>
            </div>
        </div>
        <div class="detail-section">
            <div class="detail-section-title">主体信息</div>
            <div class="detail-item">
                <span class="detail-item-label">类型</span>
                <span class="detail-item-value">${alert.subject?.type || '-'}</span>
            </div>
            <div class="detail-item">
                <span class="detail-item-label">ID</span>
                <span class="detail-item-value">${alert.subject?.id || '-'}</span>
            </div>
        </div>
        <div class="detail-section">
            <div class="detail-section-title">客体信息</div>
            <div class="detail-item">
                <span class="detail-item-label">类型</span>
                <span class="detail-item-value">${alert.object?.type || '-'}</span>
            </div>
            <div class="detail-item">
                <span class="detail-item-label">路径</span>
                <span class="detail-item-value" style="word-break:break-all;">${alert.object?.path || '-'}</span>
            </div>
        </div>
    `;

    panel.classList.add('show');
}

/**
 * 关闭散点详情面板
 */
function closeScatterDetailPanel() {
    const panel = document.getElementById('scatterDetailPanel');
    if (panel) {
        panel.classList.remove('show');
    }
}

/**
 * 初始化甘特图（使用 ECharts）
 */
function initGanttChart(alerts, startTime, endTime) {
    const chartContainer = document.getElementById('ganttMainChart');
    if (!chartContainer) return;

    if (window.ganttChartInstance) {
        window.ganttChartInstance.dispose();
    }

    // 准备图表数据
    const chartData = alerts.map((alert, index) => {
        const alertTime = new Date(alert.timestamp).getTime();
        const severityClass = alert.rule?.severity || 'low';
        const ruleInfo = RULE_DEFINITIONS[alert.rule?.rule_id] || { name: '未知规则' };

        return {
            name: alert.rule?.rule_id || 'unknown',
            value: [
                index,
                alertTime,
                alertTime + 60000,
                severityClass,
                alert.message || ruleInfo.name,
                alert.event_id || index
            ],
            itemStyle: {
                color: severityClass === 'high' ? '#e74c3c' : severityClass === 'medium' ? '#f39c12' : '#27ae60'
            }
        };
    });

    window.ganttChartInstance = echarts.init(chartContainer);

    const option = {
        tooltip: {
            formatter: function(params) {
                const data = params.data;
                const time = new Date(data.value[1]).toLocaleString('zh-CN');
                return `
                    <div style="padding: 8px;">
                        <div><strong>${data.value[3]}</strong></div>
                        <div style="color: #bdc3c7; font-size: 12px; margin-top: 4px;">${time}</div>
                        <div style="margin-top: 4px;">${escapeHtml(data.value[4])}</div>
                    </div>
                `;
            }
        },
        grid: {
            top: 40,
            left: 100,
            right: 40,
            bottom: 40
        },
        xAxis: {
            type: 'time',
            min: startTime,
            max: endTime,
            axisLabel: {
                color: '#bdc3c7',
                formatter: function(value) {
                    const date = new Date(value);
                    return date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
                }
            },
            axisLine: { lineStyle: { color: '#3d3d3d' } },
            splitLine: { lineStyle: { color: '#2d2d2d' } }
        },
        yAxis: {
            type: 'category',
            data: alerts.map((_, i) => `Alert ${i + 1}`),
            axisLabel: { show: false },
            axisLine: { show: false },
            axisTick: { show: false }
        },
        series: [{
            type: 'bar',
            coordinateSystem: 'cartesian2d',
            data: chartData,
            barWidth: 20,
            encode: {
                x: [1, 2],
                y: 0
            }
        }]
    };

    window.ganttChartInstance.setOption(option);

    // 点击事件
    window.ganttChartInstance.on('click', function(params) {
        const eventId = params.data.value[5];
        showAlertTrace(eventId);
    });
}

/**
 * 渲染规则列表视图
 */
function renderRulesListView() {
    const tableBody = document.getElementById('rulesTableBody');
    if (!tableBody) return;

    if (rulesState.data.alerts.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="7" class="no-data-message">暂无告警数据</td></tr>';
        return;
    }

    // 按时间排序
    const sortedAlerts = [...rulesState.data.alerts].sort((a, b) =>
        new Date(b.timestamp || 0) - new Date(a.timestamp || 0)
    );

    // 应用过滤器
    let filteredAlerts = sortedAlerts;
    if (rulesState.filter.severity) {
        filteredAlerts = filteredAlerts.filter(a => a.rule?.severity === rulesState.filter.severity);
    }
    if (rulesState.filter.category) {
        const categoryRules = RULE_CATEGORIES[rulesState.filter.category].rules;
        filteredAlerts = filteredAlerts.filter(a =>
            categoryRules.includes(a.rule?.rule_id)
        );
    }

    let html = '';
    filteredAlerts.forEach((alert, index) => {
        const time = alert.timestamp ? new Date(alert.timestamp).toLocaleString('zh-CN') : '未知时间';
        const severityClass = alert.rule?.severity || 'low';
        const ruleId = alert.rule?.rule_id || 'unknown';
        const ruleInfo = RULE_DEFINITIONS[ruleId] || { name: '未知规则', category: 'unknown' };

        html += `
            <tr class="rule-row" onclick="showAlertTrace('${alert.event_id || index}')">
                <td>${escapeHtml(ruleId)}</td>
                <td>
                    <a href="#" class="rule-link" onclick="event.stopPropagation(); showRuleDetail('${ruleId}')">
                        ${escapeHtml(ruleInfo.name)}
                    </a>
                </td>
                <td>
                    <span class="category-badge category-${ruleInfo.category}">
                        ${RULE_CATEGORIES[ruleInfo.category]?.name || ruleInfo.category}
                    </span>
                </td>
                <td><span class="severity-badge severity-${severityClass}">${severityClass.toUpperCase()}</span></td>
                <td>${escapeHtml(alert.subject?.name || '-')}</td>
                <td>${escapeHtml(alert.object?.name || alert.object?.path || '-')}</td>
                <td>${time}</td>
            </tr>
        `;
    });

    tableBody.innerHTML = html || '<tr><td colspan="7" class="no-data-message">没有符合条件的告警</td></tr>';
}

/**
 * 按严重程度过滤
 */
function filterBySeverity(severity) {
    rulesState.filter.severity = severity === 'all' ? null : severity;
    updateFilterStatus();
    if (rulesState.currentView === 'timeline') {
        renderTimelineView();
    } else if (rulesState.currentView === 'list') {
        renderRulesListView();
    }
}

/**
 * 按分类过滤
 */
function filterByCategory(category) {
    rulesState.filter.category = category === 'all' ? null : category;
    updateFilterStatus();
    if (rulesState.currentView !== 'list') {
        switchRulesView('list');
    } else {
        renderRulesListView();
    }
}

/**
 * 清除过滤器
 */
function clearFilter() {
    rulesState.filter.severity = null;
    rulesState.filter.category = null;
    updateFilterStatus();
    loadRulesViewData();
}

/**
 * 更新过滤器状态显示
 */
function updateFilterStatus() {
    const container = document.getElementById('filterStatus');
    if (!container) return;

    const severityText = rulesState.filter.severity ? rulesState.filter.severity.toUpperCase() : '全部';
    const categoryText = rulesState.filter.category ?
        RULE_CATEGORIES[rulesState.filter.category]?.name : '全部';

    container.innerHTML = `
        <span class="filter-active">
            <span>🔍 当前筛选:</span>
            <span id="currentFilterText">严重程度: ${severityText} | 分类: ${categoryText}</span>
            <button class="clear-filter-btn" onclick="clearFilter()">✕ 清除</button>
        </span>
    `;
    container.style.display = 'block';
}

/**
 * 显示规则详情
 */
function showRuleDetail(ruleId) {
    const rule = RULE_DEFINITIONS[ruleId];
    if (!rule) return;

    const alerts = rulesState.data.alertsByRule[ruleId] || [];

    // 使用HTML中实际的元素ID
    const titleEl = document.getElementById('ruleDetailTitle');
    const idEl = document.getElementById('ruleDetailId');
    const descEl = document.getElementById('ruleDetailDesc');
    const logicEl = document.getElementById('ruleDetailLogic');
    const triggerCountEl = document.getElementById('ruleTriggerCount');
    const alertsEl = document.getElementById('ruleDetailAlerts');

    if (titleEl) titleEl.textContent = `${ruleId}: ${rule.name}`;
    if (idEl) idEl.textContent = ruleId;
    if (descEl) descEl.textContent = rule.description || '-';
    if (logicEl) logicEl.textContent = `Mitre ATT&CK: ${rule.mitre || '-'} | 战术: ${rule.tactics || '-'}`;
    if (triggerCountEl) triggerCountEl.textContent = alerts.length;

    // 显示触发该规则的告警列表
    if (alertsEl && alerts.length > 0) {
        alertsEl.innerHTML = alerts.slice(0, 10).map(alert => `
            <div class="alert-item" style="padding: 8px; border-left: 3px solid ${alert.rule?.severity === 'high' ? '#e74c3c' : alert.rule?.severity === 'medium' ? '#f39c12' : '#27ae60'}; background: var(--card-bg); margin-bottom: 8px; border-radius: 4px;">
                <div style="font-size: 0.85rem; color: var(--text-secondary);">${alert.timestamp ? new Date(alert.timestamp).toLocaleString('zh-CN') : '未知时间'}</div>
                <div style="margin-top: 4px;">${escapeHtml(alert.message || '-')}</div>
            </div>
        `).join('') + (alerts.length > 10 ? `<div style="text-align: center; color: var(--text-secondary); padding: 10px;">...还有 ${alerts.length - 10} 条告警</div>` : '');
    } else if (alertsEl) {
        alertsEl.innerHTML = '<p style="color: var(--text-secondary); text-align: center;">暂无触发记录</p>';
    }

    showModal('ruleDetailModal');
}

/**
 * 显示告警追踪
 */
function showAlertTrace(eventId) {
    const alert = rulesState.data.alerts.find(a => a.event_id === eventId || a.event_id == eventId);
    if (!alert) return;

    const ruleId = alert.rule?.rule_id || 'unknown';
    const rule = RULE_DEFINITIONS[ruleId];

    // 使用HTML中实际的元素ID
    const alertIdEl = document.getElementById('traceAlertId');
    const ruleNameEl = document.getElementById('traceRuleName');
    const timeEl = document.getElementById('traceTime');
    const timelineEl = document.getElementById('traceTimeline');

    if (alertIdEl) alertIdEl.textContent = eventId;
    if (ruleNameEl) ruleNameEl.textContent = rule?.name || '未知规则';
    if (timeEl) timeEl.textContent = alert.timestamp ? new Date(alert.timestamp).toLocaleString('zh-CN') : '未知时间';

    // 构建时间线
    if (timelineEl) {
        timelineEl.innerHTML = `
            <div class="trace-event">
                <div class="trace-dot"></div>
                <div class="trace-content">
                    <div class="trace-time">${alert.timestamp ? new Date(alert.timestamp).toLocaleString('zh-CN') : '未知时间'}</div>
                    <div class="trace-message">${escapeHtml(alert.message || '-')}</div>
                    <div class="trace-details">
                        <div><strong>主体:</strong> ${alert.subject?.type || '-'}:${alert.subject?.name || '-'}</div>
                        <div><strong>客体:</strong> ${alert.object?.type || '-'}:${alert.object?.path || alert.object?.name || '-'}</div>
                        <div><strong>动作:</strong> ${alert.action || '-'}</div>
                        <div><strong>严重程度:</strong> <span style="color: ${alert.rule?.severity === 'high' ? '#e74c3c' : alert.rule?.severity === 'medium' ? '#f39c12' : '#27ae60'}">${(alert.rule?.severity || 'low').toUpperCase()}</span></div>
                    </div>
                </div>
            </div>
        `;
    }

    showModal('alertTraceModal');
}

/**
 * 导出报告
 */
async function exportReport(format) {
    if (format === 'json') {
        downloadJSON();
    } else if (format === 'excel') {
        exportToExcel();
    } else if (format === 'pdf') {
        alert('PDF 导出功能开发中，请使用 JSON 或 Excel 格式');
    }
}

/**
 * 下载JSON
 */
function downloadJSON() {
    const data = {
        export_time: new Date().toISOString(),
        total_alerts: rulesState.data.alerts.length,
        alerts_by_severity: {
            high: rulesState.data.alerts.filter(a => a.rule?.severity === 'high').length,
            medium: rulesState.data.alerts.filter(a => a.rule?.severity === 'medium').length,
            low: rulesState.data.alerts.filter(a => a.rule?.severity === 'low').length
        },
        alerts_by_rule: Object.fromEntries(
            Object.entries(rulesState.data.alertsByRule).map(([k, v]) => [k, v.length])
        ),
        alerts: rulesState.data.alerts
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `rules_alerts_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * 导出Excel
 */
function exportToExcel() {
    const headers = ['时间', '规则ID', '规则名称', '严重程度', '主体', '客体', '动作', '消息'];
    const rows = rulesState.data.alerts.map(alert => [
        alert.timestamp || '',
        alert.rule?.rule_id || '',
        alert.rule?.rule_name || '',
        alert.rule?.severity || '',
        `${alert.subject?.type || ''}:${alert.subject?.name || ''}`,
        `${alert.object?.type || ''}:${alert.object?.path || alert.object?.name || ''}`,
        alert.action || '',
        alert.message || ''
    ]);

    const csv = [headers, ...rows]
        .map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
        .join('\n');

    const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `rules_alerts_${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
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

// 导出到全局，供HTML中的onclick使用
window.switchRulesView = switchRulesView;
window.filterBySeverity = filterBySeverity;
window.filterByCategory = filterByCategory;
window.clearFilter = clearFilter;
window.showRuleDetail = showRuleDetail;
window.showAlertTrace = showAlertTrace;
window.exportReport = exportReport;

// 覆盖main.js中的占位函数
window.TraceEye = window.TraceEye || {};
window.TraceEye.loadRulesData = loadRulesData;
window.executeStep = executeStep;
