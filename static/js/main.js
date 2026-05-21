/**
 * Trace-Eye Demo - 主入口文件
 * SPA 架构，使用组件化加载
 */

// ==================== 全局状态 ====================

// 当前页面
let currentPage = 'overview';

// 页面配置
const PAGES = ['overview', 'upload', 'extract', 'graph', 'rules', 'threat', 'relations', 'chains', 'ai'];

// 页面依赖关系
const PAGE_DEPENDENCIES = {
    'upload': [],
    'extract': ['upload'],
    'graph': ['extract'],
    'rules': ['graph'],
    'threat': ['rules'],
    'relations': ['threat'],
    'chains': ['relations'],
    'ai': ['chains']
};

// 数据缓存
let pageData = {};

// 分页状态
const alertsPagination = {
    page: 1,
    pageSize: 20,
    total: 0,
    totalPages: 0
};

const relationsPagination = {
    page: 1,
    pageSize: 20,
    total: 0,
    totalPages: 0
};

// 规则检测状态
const rulesState = {
    currentView: 'dashboard',
    filter: {
        severity: null,
        category: null
    },
    data: {
        alerts: [],
        alertsByRule: {},
        alertsByTime: {}
    }
};

// 规则定义 (25条规则) - 导出给组件使用
const RULE_DEFINITIONS = {
    'R001': { id: 'R001', name: '敏感目录写入', category: 'file', severity: 'high', description: '检测进程是否向系统敏感目录写入数据', mitre: 'T1012', tactics: 'Credential Access' },
    'R002': { id: 'R002', name: '临时目录可执行文件写入', category: 'file', severity: 'high', description: '检测向临时目录写入可执行文件', mitre: 'T1059', tactics: 'Execution' },
    'R003': { id: 'R003', name: '浏览器写入可执行库', category: 'file', severity: 'medium', description: '检测浏览器进程向可执行目录写入文件', mitre: 'T1190', tactics: 'Initial Access' },
    'R004': { id: 'R004', name: '网络服务读取敏感文件', category: 'file', severity: 'high', description: '检测网络服务进程读取系统敏感文件', mitre: 'T1005', tactics: 'Discovery' },
    'R005': { id: 'R005', name: '进程删除自身可执行文件', category: 'file', severity: 'medium', description: '检测进程删除其自身可执行文件', mitre: 'T1070', tactics: 'Defense Evasion' },
    'R006': { id: 'R006', name: '未知进程写入系统目录', category: 'file', severity: 'medium', description: '检测非系统进程向系统目录写入文件', mitre: 'T1012', tactics: 'Credential Access' },
    'R101': { id: 'R101', name: '从临时目录执行', category: 'process', severity: 'high', description: '检测从临时目录执行可执行文件', mitre: 'T1059', tactics: 'Execution' },
    'R102': { id: 'R102', name: '父子进程命名不匹配', category: 'process', severity: 'medium', description: '检测父进程与子进程名称不匹配', mitre: 'T1059', tactics: 'Execution' },
    'R103': { id: 'R103', name: '系统进程异常子进程', category: 'process', severity: 'high', description: '检测系统进程启动非常规子进程', mitre: 'T1059', tactics: 'Execution' },
    'R104': { id: 'R104', name: '命令行包含编码内容', category: 'process', severity: 'high', description: '检测命令行中包含base64等编码', mitre: 'T1027', tactics: 'Defense Evasion' },
    'R105': { id: 'R105', name: '无父进程异常', category: 'process', severity: 'medium', description: '检测没有父进程的异常进程', mitre: 'T1059', tactics: 'Execution' },
    'R106': { id: 'R106', name: '短周期多次执行', category: 'process', severity: 'low', description: '检测同一进程短时间多次执行', mitre: 'T1059', tactics: 'Execution' },
    'R201': { id: 'R201', name: '连接非白名单境外IP', category: 'network', severity: 'high', description: '检测连接到非白名单境外IP', mitre: 'T1071', tactics: 'Command and Control' },
    'R202': { id: 'R202', name: '非网络客户端建立连接', category: 'network', severity: 'medium', description: '检测非网络客户端进程建立网络连接', mitre: 'T1071', tactics: 'Command and Control' },
    'R203': { id: 'R203', name: '系统进程连接非常用端口', category: 'network', severity: 'medium', description: '检测系统进程连接到非常用端口', mitre: 'T1071', tactics: 'Command and Control' },
    'R204': { id: 'R204', name: '监听高位端口', category: 'network', severity: 'low', description: '检测进程监听高位端口(>1024)', mitre: 'T1059', tactics: 'Execution' },
    'R205': { id: 'R205', name: '短时间多IP连接', category: 'network', severity: 'high', description: '检测短时间连接多个不同IP', mitre: 'T1071', tactics: 'Command and Control' },
    'R301': { id: 'R301', name: '文件下载后立即执行', category: 'sequence', severity: 'high', description: '检测文件下载后立即执行的序列', mitre: 'T1105', tactics: 'Execution' },
    'R302': { id: 'R302', name: '进程启动后连接外部', category: 'sequence', severity: 'medium', description: '检测进程启动后立即连接外网', mitre: 'T1071', tactics: 'Command and Control' },
    'R303': { id: 'R303', name: '读敏感文件后联网', category: 'sequence', severity: 'high', description: '检测读取敏感文件后立即联网', mitre: 'T1041', tactics: 'Exfiltration' },
    'R304': { id: 'R304', name: '修改启动项', category: 'sequence', severity: 'high', description: '检测修改启动项以实现持久化', mitre: 'T1547', tactics: 'Persistence' },
    'R305': { id: 'R305', name: '多进程写入同一文件', category: 'sequence', severity: 'medium', description: '检测多个进程写入同一文件', mitre: 'T1012', tactics: 'Credential Access' },
    'R401': { id: 'R401', name: '凌晨异常活动', category: 'temporal', severity: 'medium', description: '检测凌晨时段(0:00-6:00)的活动', mitre: 'T1078', tactics: 'Defense Evasion' },
    'R402': { id: 'R402', name: '周末系统操作', category: 'temporal', severity: 'low', description: '检测周末时段的系统操作', mitre: 'T1078', tactics: 'Defense Evasion' },
    'R403': { id: 'R403', name: '频繁失败尝试', category: 'temporal', severity: 'medium', description: '检测短时间内频繁的失败操作', mitre: 'T1110', tactics: 'Credential Access' }
};

// 规则分类配置
const RULE_CATEGORIES = {
    'file': { name: '文件异常', icon: 'fa-file-alt', color: '#e74c3c', rules: ['R001', 'R002', 'R003', 'R004', 'R005', 'R006'] },
    'process': { name: '进程异常', icon: 'fa-cogs', color: '#f39c12', rules: ['R101', 'R102', 'R103', 'R104', 'R105', 'R106'] },
    'network': { name: '网络异常', icon: 'fa-globe', color: '#3498db', rules: ['R201', 'R202', 'R203', 'R204', 'R205'] },
    'sequence': { name: '行为序列', icon: 'fa-list-ol', color: '#9b59b6', rules: ['R301', 'R302', 'R303', 'R304', 'R305'] },
    'temporal': { name: '时序异常', icon: 'fa-clock', color: '#1abc9c', rules: ['R401', 'R402', 'R403'] }
};

// ==================== 页面名称 ====================

const PAGE_NAMES = {
    'overview': '系统总览',
    'upload': '数据准备',
    'extract': '事件提取',
    'graph': '关系图构建',
    'rules': '规则检测',
    'threat': '威胁检测',
    'relations': '关系挖掘',
    'chains': '攻击链重建',
    'ai': 'AI 分析'
};

// ==================== 初始化 ====================

document.addEventListener('DOMContentLoaded', async () => {
    // 加载组件加载器
    const loaderScript = document.createElement('script');
    loaderScript.src = '/static/js/utils/component-loader.js';
    document.head.appendChild(loaderScript);

    loaderScript.onload = async () => {
        // 初始化路由
        initRouter();

        // 初始化按钮状态
        try {
            const status = await getSystemStatus();
            updateNavigationStatus(status);
        } catch (e) {
            console.error('获取初始状态失败:', e);
        }

        // 加载初始页面
        const hash = window.location.hash.replace('#page-', '') || 'upload';
        await navigateTo(hash);
    };

    // 绑定全局事件
    bindGlobalEvents();

    // 启动状态轮询
    startStatusPolling();
});

// ==================== 路由功能 ====================

function initRouter() {
    // 监听 hash 变化
    window.addEventListener('hashchange', () => {
        const hash = window.location.hash.replace('#page-', '');
        if (hash && hash !== currentPage) {
            navigateTo(hash);
        }
    });
}

async function navigateTo(pageId) {
    if (!PAGES.includes(pageId)) {
        console.error(`未知页面: ${pageId}`);
        return;
    }

    // 更新当前页面
    currentPage = pageId;

    // 切换导航状态
    updateNavigation(pageId);

    // 更新顶部标题
    document.getElementById('currentStepName').textContent = PAGE_NAMES[pageId] || '';

    // 加载页面组件
    try {
        await ComponentLoader.load(pageId);
    } catch (error) {
        console.error(`加载页面 ${pageId} 失败:`, error);
    }

    // 加载页面数据
    await loadPageData(pageId);

    // 更新 URL hash
    if (window.location.hash !== `#page-${pageId}`) {
        history.pushState(null, null, `#page-${pageId}`);
    }
}

function updateNavigation(pageId) {
    // 更新侧边栏导航状态
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.dataset.page === pageId) {
            item.classList.add('active');
        }
    });
}

// ==================== 页面数据加载 ====================

async function loadPageData(pageId) {
    try {
        // 获取系统状态（不使用缓存）
        const status = await getSystemStatus();

        // 转换 steps_status 格式
        const stepsCompleted = {};
        if (status.steps_status) {
            for (const [stepId, stepInfo] of Object.entries(status.steps_status)) {
                stepsCompleted[stepId] = stepInfo.completed;
            }
        }
        status.steps_completed = stepsCompleted;

        // 检查当前步骤是否完成
        const currentStepCompleted = stepsCompleted[pageId];

        // 检查依赖
        const dependencies = PAGE_DEPENDENCIES[pageId] || [];
        const canProceed = dependencies.every(dep => stepsCompleted[dep]);

        if (!canProceed && dependencies.length > 0) {
            showInputEmpty(pageId, dependencies[dependencies.length - 1]);
            return;
        }

        // 隐藏空状态
        hideInputEmpty(pageId);

        // 只有当前步骤完成时，才加载该步骤的数据
        let pageDataCache = null;
        if (currentStepCompleted) {
            pageDataCache = await DataCache.get(pageId);
            console.log(`[Load] ${pageId} step completed, data loaded`);
        } else {
            console.log(`[Load] ${pageId} step not completed, showing input only`);
        }

        // 根据页面加载不同数据
        switch (pageId) {
            case 'overview':
                await loadOverviewData(status, pageDataCache);
                break;
            case 'upload':
                await loadUploadData(status, pageDataCache);
                break;
            case 'extract':
                await loadExtractData(status, pageDataCache);
                break;
            case 'graph':
                await loadGraphData(status, pageDataCache);
                break;
            case 'rules':
                await loadRulesData(status, pageDataCache);
                break;
            case 'threat':
                await loadThreatData(status, pageDataCache);
                break;
            case 'relations':
                await (window.TraceEye?.loadRelationsData || loadRelationsData)(status, pageDataCache);
                break;
            case 'chains':
                await loadChainsData(status, pageDataCache);
                break;
            case 'ai':
                await loadAIData(status, pageDataCache);
                break;
        }

        // 更新顶部统计和按钮状态
        updateTopStats(status);
        updateNavigationStatus(status);

    } catch (error) {
        console.error(`加载页面 ${pageId} 数据失败:`, error);
    }
}

// ==================== 全局事件绑定 ====================

function bindGlobalEvents() {
    // 重置按钮
    document.getElementById('btnReset')?.addEventListener('click', async () => {
        if (confirm('确定要重置系统吗？所有数据将被清空。')) {
            try {
                await resetSystem();
                location.reload();
            } catch (error) {
                alert('重置失败: ' + error.message);
            }
        }
    });
}

// ==================== 状态轮询 ====================

function startStatusPolling() {
    // 每 5 秒轮询一次状态
    setInterval(async () => {
        try {
            const status = await getSystemStatus();
            updateTopStats(status);
            updateNavigationStatus(status);
        } catch (error) {
            console.error('状态轮询错误:', error);
        }
    }, 5000);
}

function updateTopStats(status) {
    const stats = status.stats || {};
    document.getElementById('statTotalEvents').textContent = stats.total_events || '-';
    document.getElementById('statAlerts').textContent = stats.total_alerts || '-';
    document.getElementById('statThreatLevel').textContent = stats.threat_level || '-';
}

function updateNavigationStatus(status) {
    // 更新每个导航项的状态图标
    for (const [page, pageStatus] of Object.entries(status.steps_status || {})) {
        const navStatus = document.getElementById(`navStatus${page.charAt(0).toUpperCase() + page.slice(1)}`);
        if (navStatus) {
            if (pageStatus.completed) {
                navStatus.textContent = '✓';
                navStatus.style.color = 'var(--success-color)';
            } else if (pageStatus.running) {
                navStatus.textContent = '⏳';
                navStatus.style.color = 'var(--warning-color)';
            } else {
                navStatus.textContent = '';
            }
        }
    }

    // 更新各页面按钮启用状态
    updatePageButtons(status);
}

/**
 * 更新各页面处理按钮的启用状态
 */
function updatePageButtons(status) {
    const stepsCompleted = {};
    if (status.steps_status) {
        for (const [stepId, stepInfo] of Object.entries(status.steps_status)) {
            stepsCompleted[stepId] = stepInfo.completed;
        }
    }
    status.steps_completed = stepsCompleted;

    console.log('[updatePageButtons] stepsCompleted:', stepsCompleted);

    // 每个页面的按钮启用条件（依赖步骤）
    const buttonConditions = {
        'extract': 'upload',
        'graph': 'extract',
        'rules': 'graph',
        'threat': 'rules',
        'relations': 'threat',
        'chains': 'relations',
        'ai': 'chains'
    };

    for (const [page, dependency] of Object.entries(buttonConditions)) {
        const buttonIds = {
            ai: 'btnAIAnalyze'
        };
        const btnId = buttonIds[page] || `btn${page.charAt(0).toUpperCase() + page.slice(1)}`;
        const btn = document.getElementById(btnId);
        const canExecute = status.steps_completed[dependency];

        console.log(`[updatePageButtons] page=${page}, btnId=${btnId}, exists=${!!btn}, dependency=${dependency}, canExecute=${canExecute}`);

        if (btn) {
            btn.disabled = !canExecute;
            if (canExecute) {
                btn.title = '';
            } else {
                btn.title = `请先完成 ${PAGE_NAMES[dependency] || dependency}`;
            }
        }
    }
}

// ==================== 工具函数 ====================

function showInputEmpty(pageId, depPage) {
    const depNames = PAGE_NAMES;
    const emptyDiv = document.getElementById(`${pageId}InputEmpty`);
    if (emptyDiv) {
        emptyDiv.innerHTML = `<p>暂无数据，请先完成 <a href="#page-${depPage}" onclick="navigateTo('${depPage}')">${depNames[depPage]}</a></p>`;
        emptyDiv.style.display = 'block';
    }
    const filledDiv = document.getElementById(`${pageId}InputFilled`);
    if (filledDiv) {
        filledDiv.style.display = 'none';
    }
}

function hideInputEmpty(pageId) {
    const emptyDiv = document.getElementById(`${pageId}InputEmpty`);
    if (emptyDiv) {
        emptyDiv.style.display = 'none';
    }
    const filledDiv = document.getElementById(`${pageId}InputFilled`);
    if (filledDiv) {
        filledDiv.style.display = 'block';
    }
}

function showOutputSection(section) {
    const outputSection = document.getElementById(`${section}OutputSection`);
    if (outputSection) {
        outputSection.style.display = 'block';
    }
}

function showDownloadButton(section) {
    const downloadBtn = document.getElementById(`download${section.charAt(0).toUpperCase() + section.slice(1)}`);
    if (downloadBtn) {
        downloadBtn.style.display = 'inline-block';
    }
}

// ==================== 页面数据加载函数 ====================

// 这些函数将由各个页面组件的具体实现覆盖
// 这里只提供占位符

async function loadOverviewData(status) {
    // 由 overview.js 实现
}

async function loadUploadData(status) {
    // 由 upload.js 实现
}

async function loadExtractData(status) {
    // 由 extract.js 实现
}

async function loadGraphData(status) {
    // 由 graph.js 实现
}

async function loadRulesData(status) {
    // 由 rules.js 实现
}

async function loadThreatData(status) {
    // 由 threat.js 实现
}

async function loadRelationsData(status) {
    // 由 relations.js 实现
}

async function loadChainsData(status) {
    // 由 chains.js 实现
}

async function loadAIData(status) {
    // 由 ai.js 实现
}

// ==================== 导出全局变量 ====================

window.TraceEye = {
    currentPage,
    rulesState,
    alertsPagination,
    relationsPagination,
    RULE_DEFINITIONS,
    RULE_CATEGORIES,
    navigateTo,
    loadPageData,
    showOutputSection,
    showDownloadButton
};
