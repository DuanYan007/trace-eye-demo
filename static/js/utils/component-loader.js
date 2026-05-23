/**
 * 页面组件加载器
 * 负责动态加载页面组件的 HTML 和对应的 JavaScript
 */

// 组件配置
const COMPONENTS = {
    overview: {
        template: '/static/components/overview.html',
        script: '/static/js/components/overview.js'
    },
    upload: {
        template: '/static/components/upload.html',
        script: '/static/js/components/upload.js'
    },
    extract: {
        template: '/static/components/extract.html',
        script: '/static/js/components/extract.js'
    },
    graph: {
        template: '/static/components/graph.html',
        script: '/static/js/components/graph.js'
    },
    rules: {
        template: '/static/components/rules.html',
        script: '/static/js/components/rules.js'
    },
    threat: {
        template: '/static/components/threat.html',
        script: '/static/js/components/threat.js'
    },
    relations: {
        template: '/static/components/relations.html',
        script: '/static/js/components/relations.js'
    },
    chains: {
        template: '/static/components/chains.html',
        script: '/static/js/components/chains.js'
    },
    ai: {
        template: '/static/components/ai.html',
        script: '/static/js/components/ai.js'
    }
};

// 已加载的组件缓存
const loadedComponents = new Set();
const loadedScripts = new Set();

/**
 * 加载页面组件
 * @param {string} componentName - 组件名称
 * @param {string} containerId - 容器元素 ID
 * @returns {Promise<void>}
 */
async function loadComponent(componentName, containerId = 'pageContainer') {
    if (!COMPONENTS[componentName]) {
        console.error(`组件 "${componentName}" 不存在`);
        return;
    }

    const component = COMPONENTS[componentName];
    const container = document.getElementById(containerId);

    if (!container) {
        console.error(`容器 "${containerId}" 不存在`);
        return;
    }

    try {
        // 加载 HTML 模板
        const htmlResponse = await fetch(`${component.template}?v=${Date.now()}`);
        if (!htmlResponse.ok) {
            throw new Error(`Failed to load template: ${htmlResponse.statusText}`);
        }
        const htmlContent = await htmlResponse.text();
        container.innerHTML = htmlContent;

        // 加载 JavaScript
        if (!loadedScripts.has(componentName)) {
            await new Promise((resolve, reject) => {
                const script = document.createElement('script');
                script.src = `${component.script}?v=${Date.now()}`;
                script.onload = () => {
                    loadedScripts.add(componentName);
                    console.log(`组件 "${componentName}" 脚本加载完成`);
                    resolve();
                };
                script.onerror = () => {
                    reject(new Error(`组件 "${componentName}" 脚本加载失败`));
                };
                document.body.appendChild(script);
            });
        }

        loadedComponents.add(componentName);
        console.log(`组件 "${componentName}" 加载完成`);

        // 触发自定义事件，通知组件已加载
        window.dispatchEvent(new CustomEvent('componentLoaded', {
            detail: { name: componentName }
        }));

    } catch (error) {
        console.error(`加载组件 "${componentName}" 失败:`, error);
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">⚠️</div>
                <div class="empty-state-title">加载失败</div>
                <div class="empty-state-desc">组件加载失败: ${error.message}</div>
            </div>
        `;
    }
}

/**
 * 预加载组件
 * @param {string[]} componentNames - 要预加载的组件名称列表
 */
async function preloadComponents(componentNames) {
    for (const name of componentNames) {
        if (!loadedComponents.has(name)) {
            await loadComponent(name);
        }
    }
}

/**
 * 检查组件是否已加载
 * @param {string} componentName - 组件名称
 * @returns {boolean}
 */
function isComponentLoaded(componentName) {
    return loadedComponents.has(componentName);
}

/**
 * 卸载组件
 * @param {string} componentName - 组件名称
 */
function unloadComponent(componentName) {
    // 清理组件相关的事件监听器和数据
    const event = new CustomEvent('componentUnload', {
        detail: { name: componentName }
    });
    window.dispatchEvent(event);

    loadedComponents.delete(componentName);
    console.log(`组件 "${componentName}" 已卸载`);
}

// 导出组件加载器
window.ComponentLoader = {
    load: loadComponent,
    preload: preloadComponents,
    isLoaded: isComponentLoaded,
    unload: unloadComponent,
    COMPONENTS
};
