/**
 * API 请求工具函数
 */

// API 基础配置
const API_BASE = '/api';
const REQUEST_TIMEOUT = 30000;

/**
 * 通用 API 请求函数
 * @param {string} endpoint - API 端点
 * @param {Object} options - 请求选项
 * @returns {Promise} Promise 对象
 */
async function apiRequest(endpoint, options = {}) {
    const url = endpoint.startsWith('http') ? endpoint : `${API_BASE}${endpoint}`;

    const config = {
        method: options.method || 'GET',
        headers: {
            'Content-Type': 'application/json',
            ...options.headers
        },
        ...options
    };

    if (options.body && config.method !== 'GET') {
        config.body = JSON.stringify(options.body);
    }

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

        const response = await fetch(url, {
            ...config,
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return await response.json();
        }
        return await response.text();

    } catch (error) {
        if (error.name === 'AbortError') {
            throw new Error('请求超时，请稍后重试');
        }
        console.error('API 请求失败:', error);
        throw error;
    }
}

/**
 * GET 请求
 */
function apiGet(endpoint, params = {}) {
    const queryString = new URLSearchParams(params).toString();
    const url = queryString ? `${endpoint}?${queryString}` : endpoint;
    return apiRequest(url);
}

/**
 * POST 请求
 */
function apiPost(endpoint, data = {}) {
    return apiRequest(endpoint, {
        method: 'POST',
        body: data
    });
}

/**
 * PUT 请求
 */
function apiPut(endpoint, data = {}) {
    return apiRequest(endpoint, {
        method: 'PUT',
        body: data
    });
}

/**
 * DELETE 请求
 */
function apiDelete(endpoint) {
    return apiRequest(endpoint, {
        method: 'DELETE'
    });
}

// ==================== 系统状态 API ====================

/**
 * 获取系统状态
 */
function getSystemStatus() {
    return apiGet('/status');
}

/**
 * 重置系统
 */
function resetSystem() {
    return apiPost('/reset');
}

// ==================== 数据操作 API ====================

/**
 * 上传日志文件
 * @param {FormData} formData - 包含文件的 FormData 对象
 */
function uploadLogs(formData) {
    return fetch(`${API_BASE}/upload`, {
        method: 'POST',
        body: formData
    }).then(response => response.json());
}

/**
 * 生成测试数据
 */
function generateTestData(params = {}) {
    return apiPost('/generate', params);
}

// ==================== 步骤执行 API ====================

/**
 * 执行事件提取
 */
function executeExtract() {
    return apiPost('/step/extract');
}

/**
 * 执行关系图构建
 */
function executeGraph() {
    return apiPost('/step/graph');
}

/**
 * 执行规则检测
 */
function executeRules() {
    return apiPost('/step/rules');
}

/**
 * 执行威胁检测
 */
function executeThreat() {
    return apiPost('/step/threat');
}

/**
 * 执行关系挖掘
 */
function executeRelations() {
    return apiPost('/step/relations');
}

/**
 * 执行攻击链重建
 */
function executeChains() {
    return apiPost('/step/chains');
}

// ==================== 数据获取 API ====================

/**
 * 获取事件列表
 */
function getEvents(params = {}) {
    return apiGet('/events', params);
}

/**
 * 获取关系图数据
 */
function getGraph() {
    return apiGet('/graph');
}

/**
 * 获取告警列表
 */
function getAlerts(params = {}) {
    return apiGet('/alerts', params);
}

/**
 * 获取威胁检测结果
 */
function getThreat() {
    return apiGet('/threat');
}

/**
 * 获取关系挖掘结果
 */
function getRelations() {
    return apiGet('/relations');
}

/**
 * 获取攻击链结果
 */
function getChains() {
    return apiGet('/chains');
}

/**
 * 获取完整分析结果
 */
function getAnalysis() {
    return apiGet('/analysis');
}

/**
 * 获取攻击场景统计
 */
function getScenarios() {
    return apiGet('/scenarios');
}

/**
 * 获取已上传日志信息
 */
function getLogsInfo() {
    return apiGet('/logs/info');
}

/**
 * 获取步骤缓存数据
 */
function getCache(step) {
    return apiGet(`/cache/${step}`);
}

/**
 * 获取所有缓存状态
 */
function getAllCache() {
    return apiGet('/cache/all');
}

// ==================== AI 分析 API ====================

/**
 * 获取 LLM 服务状态
 */
function getLLMStatus() {
    return apiGet('/llm/status');
}

/**
 * 执行 AI 分析
 */
function executeAIAnalysis() {
    return apiPost('/llm/analyze');
}

/**
 * 获取 AI 分析结果
 */
function getAIResult() {
    return apiGet('/llm/result');
}

// ==================== 数据下载 API ====================

/**
 * 下载数据文件
 * @param {string} fileType - 文件类型 (logs/events/graph/alerts/threat/relations/chains/analysis)
 */
function downloadFile(fileType) {
    window.location.href = `${API_BASE}/download/${fileType}`;
}

/**
 * 获取所有数据文件状态
 */
function getAllFiles() {
    return apiGet('/files');
}

// ==================== 导出全局函数 ====================

window.apiGet = apiGet;
window.apiPost = apiPost;
window.apiRequest = apiRequest;
