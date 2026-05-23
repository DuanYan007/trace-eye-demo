/**
 * 事件提取页面组件
 */

// 组件加载完成后的初始化
window.addEventListener('componentLoaded', (e) => {
    if (e.detail.name === 'extract') {
        initExtractPage();
    }
});

/**
 * 初始化事件提取页面
 */
function initExtractPage() {
    const page = document.getElementById('page-extract');
    if (!page || page.dataset.extractInitialized === 'true') return;
    page.dataset.extractInitialized = 'true';

    // 绑定执行按钮
    const btn = document.getElementById('btnExtract');
    if (btn) {
        btn.addEventListener('click', () => executeStep('extract', '/step/extract'));
    }
}

/**
 * 加载事件提取页面数据
 * @param {Object} status - 系统状态
 * @param {Object} pageDataCache - 页面缓存数据
 */
async function loadExtractData(status, pageDataCache) {
    // 检查upload步骤是否完成
    if (status.steps_completed?.upload) {
        document.getElementById('extractInputEmpty').style.display = 'none';
        document.getElementById('extractInputFilled').style.display = 'block';

        // 从缓存获取upload步骤的数据作为输入
        try {
            const uploadData = await DataCache.get('upload');
            const files = uploadData?.data?.files || [];

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
            const fileListDiv = document.getElementById('extractInputFileList');
            if (fileListDiv) {
                fileListDiv.innerHTML = '<p style="color: var(--text-secondary);">无法加载文件信息</p>';
            }
        }

        // 显示输出区域
        const outputSection = document.getElementById('extractOutputSection');
        if (outputSection) {
            outputSection.style.display = 'block';
        }

        // 显示输出统计（如果extract已完成）
        if (status.steps_completed?.extract) {
            await loadExtractResults(pageDataCache);
        }
    }
}

/**
 * 加载事件提取结果
 * @param {Object} pageDataCache - 页面缓存数据
 */
async function loadExtractResults(pageDataCache) {
    try {
        const extractData = pageDataCache || await DataCache.get('extract');
        const data = extractData?.data || {};
        const summary = extractData?.summary || {};

        const totalCount = summary.total_events || data.total_events || 0;
        const outTotalEl = document.getElementById('extractOutTotal');
        const eventCountEl = document.getElementById('extractEventCount');

        if (outTotalEl) outTotalEl.textContent = totalCount;
        if (eventCountEl) eventCountEl.textContent = totalCount;

        // 类型分布
        const byType = summary.by_type || data.by_type || {};
        const typeBars = document.getElementById('extractTypeBars');
        if (typeBars && Object.keys(byType).length > 0) {
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
        } else if (typeBars) {
            typeBars.innerHTML = '<p style="color: var(--text-secondary);">暂无数据</p>';
        }

        // 显示下载按钮
        const downloadBtn = document.getElementById('downloadEvents');
        if (downloadBtn) {
            downloadBtn.style.display = 'inline-block';
        }
    } catch (e) {
        console.error('Load extract cache error:', e);
    }
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
    // 先启动任务
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

            // 更新步骤状态
            updateStepDots(pageId, status.current_step);

            if (status.completed) {
                clearInterval(pollInterval);
                updateProgress(pageId, 100, '完成');

                setTimeout(async () => {
                    hideProcessSection(pageId);
                    // 清除缓存，重新加载数据
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
window.TraceEye.loadExtractData = loadExtractData;
window.executeStep = executeStep;
