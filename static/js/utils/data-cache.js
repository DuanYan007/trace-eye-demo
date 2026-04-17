/**
 * 数据缓存管理器
 * 实现懒加载 + 内存缓存，避免重复请求
 */

// 数据缓存存储
const dataCache = {
    // 系统状态（不缓存，每次都获取最新）
    status: null,

    // 各步骤数据缓存
    upload: null,
    extract: null,
    graph: null,
    rules: null,
    threat: null,
    relations: null,
    chains: null,
    ai: null
};

// 缓存时间戳（用于判断缓存是否过期）
const cacheTimestamps = {};

// 缓存有效期（毫秒）- 默认5分钟
const CACHE_TTL = 5 * 60 * 1000;

/**
 * 数据加载器配置
 * 每个页面需要加载的 API 端点
 */
const DATA_LOADERS = {
    'upload': async () => {
        return await apiGet('/cache/upload');
    },
    'extract': async () => {
        return await apiGet('/cache/extract');
    },
    'graph': async () => {
        return await apiGet('/cache/graph');
    },
    'rules': async () => {
        return await apiGet('/cache/rules');
    },
    'threat': async () => {
        return await apiGet('/cache/threat');
    },
    'relations': async () => {
        return await apiGet('/cache/relations');
    },
    'chains': async () => {
        return await apiGet('/cache/chains');
    },
    'ai': async () => {
        return await apiGet('/llm/result');
    }
};

/**
 * 检查缓存是否有效
 */
function isCacheValid(pageId) {
    if (!dataCache[pageId]) {
        return false;
    }
    if (!cacheTimestamps[pageId]) {
        return false;
    }
    const now = Date.now();
    return (now - cacheTimestamps[pageId]) < CACHE_TTL;
}

/**
 * 获取页面数据（带缓存）
 * @param {string} pageId - 页面ID
 * @param {boolean} forceRefresh - 是否强制刷新
 * @returns {Promise} 缓存的数据或新请求的数据
 */
async function getPageData(pageId, forceRefresh = false) {
    // 系统状态每次都获取最新
    if (pageId === 'status') {
        return await apiGet('/status');
    }

    // 如果有有效缓存且不强制刷新，直接返回缓存
    if (!forceRefresh && isCacheValid(pageId)) {
        console.log(`[Cache] 使用缓存数据: ${pageId}`);
        return dataCache[pageId];
    }

    // 没有缓存或缓存过期，加载数据
    if (DATA_LOADERS[pageId]) {
        console.log(`[Cache] 加载数据: ${pageId}`);
        try {
            const result = await DATA_LOADERS[pageId]();
            dataCache[pageId] = result;
            cacheTimestamps[pageId] = Date.now();
            return result;
        } catch (error) {
            console.error(`[Cache] 加载数据失败: ${pageId}`, error);
            // 如果有旧缓存，返回旧缓存
            if (dataCache[pageId]) {
                console.log(`[Cache] 使用过期缓存: ${pageId}`);
                return dataCache[pageId];
            }
            throw error;
        }
    }

    return null;
}

/**
 * 设置页面数据缓存
 * @param {string} pageId - 页面ID
 * @param {*} data - 要缓存的数据
 */
function setPageData(pageId, data) {
    dataCache[pageId] = data;
    cacheTimestamps[pageId] = Date.now();
}

/**
 * 清除指定页面的缓存
 * @param {string} pageId - 页面ID，不传则清除所有
 */
function clearPageCache(pageId = null) {
    if (pageId) {
        console.log(`[Cache] 清除缓存: ${pageId}`);
        dataCache[pageId] = null;
        delete cacheTimestamps[pageId];
    } else {
        console.log('[Cache] 清除所有缓存');
        for (const key in dataCache) {
            dataCache[key] = null;
        }
        for (const key in cacheTimestamps) {
            delete cacheTimestamps[key];
        }
    }
}

/**
 * 清除所有后续步骤的缓存
 * 当某个步骤更新时，其后续步骤的缓存都需要失效
 * @param {string} stepId - 步骤ID
 */
function clearSubsequentCache(stepId) {
    const stepOrder = ['upload', 'extract', 'graph', 'rules', 'threat', 'relations', 'chains', 'ai'];
    const stepIndex = stepOrder.indexOf(stepId);

    if (stepIndex !== -1) {
        for (let i = stepIndex; i < stepOrder.length; i++) {
            clearPageCache(stepOrder[i]);
        }
    }
}

/**
 * 获取缓存状态信息
 */
function getCacheStatus() {
    const status = {};
    for (const key in dataCache) {
        status[key] = {
            hasData: dataCache[key] !== null,
            timestamp: cacheTimestamps[key] || null,
            age: cacheTimestamps[key] ? Date.now() - cacheTimestamps[key] : null,
            isValid: isCacheValid(key)
        };
    }
    return status;
}

/**
 * 预加载多个页面的数据
 * @param {string[]} pageIds - 要预加载的页面ID列表
 */
async function preloadPages(pageIds) {
    const promises = pageIds
        .filter(id => !isCacheValid(id))
        .map(id => getPageData(id).catch(err => console.error(`预加载 ${id} 失败:`, err)));

    await Promise.all(promises);
}

// 导出缓存管理器
window.DataCache = {
    get: getPageData,
    set: setPageData,
    clear: clearPageCache,
    clearSubsequent: clearSubsequentCache,
    getStatus: getCacheStatus,
    preload: preloadPages,
    isValid: isCacheValid
};
