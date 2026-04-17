/**
 * 数据准备页面组件
 * 负责文件上传和演示模式
 */

// 选中的文件列表
let selectedFiles = [];

// 组件加载完成后的初始化
window.addEventListener('componentLoaded', (e) => {
    if (e.detail.name === 'upload') {
        initUploadPage();
    }
});

/**
 * 初始化上传页面
 */
function initUploadPage() {
    // 绑定文件选择事件
    const fileInput = document.getElementById('fileUpload');
    if (fileInput) {
        fileInput.addEventListener('change', handleFileSelect);
    }

    // 绑定清空按钮
    const clearBtn = document.getElementById('btnClearFiles');
    if (clearBtn) {
        clearBtn.addEventListener('click', clearFiles);
    }

    // 绑定上传按钮
    const uploadBtn = document.getElementById('btnUploadSelected');
    if (uploadBtn) {
        uploadBtn.addEventListener('click', uploadFiles);
    }
}

/**
 * 显示模式选择器
 */
function showModeSelector() {
    document.getElementById('modeSelector').style.display = 'flex';
    document.getElementById('uploadArea').style.display = 'none';
}

/**
 * 选择上传模式
 */
function selectUploadMode() {
    document.getElementById('modeSelector').style.display = 'none';
    document.getElementById('uploadArea').style.display = 'block';
}

/**
 * 启动演示模式
 */
async function startDemoMode() {
    try {
        showProcessSection('upload');
        updateProgress('upload', 10, '启动演示模式...');

        const response = await apiPost('/demo/start');

        if (response.error) {
            throw new Error(response.error);
        }

        updateProgress('upload', 100, '演示数据已加载');

        setTimeout(async () => {
            hideProcessSection('upload');
            // 重新加载页面数据
            await loadPageData('upload');
        }, 500);

    } catch (error) {
        hideProcessSection('upload');
        alert(`启动演示模式失败: ${error.message}`);
    }
}

/**
 * 处理文件选择
 */
function handleFileSelect(e) {
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
        const logType = detectLogType(file.name);
        return `
            <div class="file-item">
                <span class="file-item-icon">${getFileIconFromName(file.name)}</span>
                <span class="file-item-name">${escapeHtml(file.name)}</span>
                <span class="file-item-size">${formatFileSize(file.size)} | ${logType}</span>
                <span class="file-item-remove" onclick="removeFile(${index})">×</span>
            </div>
        `;
    }).join('');
}

/**
 * 移除文件
 */
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
                    <span class="file-item-size">${formatFileSize(file.size)} | ${logType}</span>
                    <span class="file-item-remove" onclick="removeFile(${i})">×</span>
                </div>
            `;
        }).join('');
    }
}

/**
 * 清空文件列表
 */
function clearFiles() {
    selectedFiles = [];
    const fileInput = document.getElementById('fileUpload');
    if (fileInput) {
        fileInput.value = '';
    }
    document.getElementById('uploadFileList').style.display = 'none';
    document.getElementById('uploadEmpty').style.display = 'block';
}

/**
 * 上传文件
 */
async function uploadFiles() {
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
            // 重新加载页面数据
            window.TraceEye?.loadPageData?.('upload');
        }, 500);

    } catch (error) {
        hideProcessSection('upload');
        alert(`上传失败: ${error.message}`);
    }
}

/**
 * 生成测试数据
 */
async function generateTestData() {
    try {
        showProcessSection('upload');
        updateProgress('upload', 0, '生成测试数据...');

        const response = await apiPost('/generate', {
            num_events: 1000,
            inject_attack: true
        });

        updateProgress('upload', 100, '生成完成');
        setTimeout(async () => {
            hideProcessSection('upload');
            window.TraceEye?.loadPageData?.('upload');
        }, 500);

    } catch (error) {
        hideProcessSection('upload');
        alert(`生成失败: ${error.message}`);
    }
}

/**
 * 加载上传页面数据
 * @param {Object} status - 系统状态
 * @param {Object} pageDataCache - 页面缓存数据
 */
async function loadUploadData(status, pageDataCache) {
    try {
        const isUploadComplete = status.steps_completed?.upload;

        if (isUploadComplete) {
            // 隐藏模式选择器和上传区域，显示结果区域
            document.getElementById('modeSelector').style.display = 'none';
            document.getElementById('uploadArea').style.display = 'none';
            document.getElementById('uploadResultSection').style.display = 'block';

            // 显示下载按钮
            const downloadBtn = document.getElementById('downloadLogs');
            if (downloadBtn) {
                downloadBtn.style.display = 'inline-block';
            }

            // 获取并显示文件列表
            await displayUploadedFiles();
        } else {
            // 显示模式选择器
            document.getElementById('modeSelector').style.display = 'flex';
            document.getElementById('uploadArea').style.display = 'none';
            document.getElementById('uploadResultSection').style.display = 'none';
        }
    } catch (error) {
        console.error('loadUploadData error:', error);
    }
}

/**
 * 显示已上传的文件列表
 * 在演示模式下显示预生成的文件信息
 */
async function displayUploadedFiles() {
    try {
        // 从 API 获取日志信息
        const logInfo = await apiGet('/logs/info');
        const files = logInfo?.files || [];

        const filesList = document.getElementById('uploadedFilesList');

        if (files.length > 0) {
            // 更新文件计数
            document.getElementById('uploadedFileCount').textContent = files.length;

            filesList.innerHTML = files.map(file => `
                <div style="display: flex; align-items: center; gap: 15px; padding: 12px; background: var(--light-bg); border-radius: 6px;">
                    <span style="font-size: 1.5rem;">${getFileIcon(file.type)}</span>
                    <div style="flex: 1;">
                        <div style="font-weight: 500;">${escapeHtml(file.name)}</div>
                        <div style="font-size: 0.85rem; color: var(--text-secondary);">
                            ${getTypeLabel(file.type)} | ${file.lines?.toLocaleString() || 0} 行
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
        // 在 demo 模式下，如果 API 调用失败，显示默认的演示文件信息
        const filesList = document.getElementById('uploadedFilesList');
        filesList.innerHTML = `
            <div style="display: flex; align-items: center; gap: 15px; padding: 12px; background: var(--light-bg); border-radius: 6px;">
                <span style="font-size: 1.5rem;">📋</span>
                <div style="flex: 1;">
                    <div style="font-weight: 500;">演示数据集</div>
                    <div style="font-size: 0.85rem; color: var(--text-secondary);">
                        多源日志 | 40000+ 事件
                    </div>
                </div>
                <span style="font-size: 0.85rem; color: var(--success-color);">✓</span>
            </div>
        `;
        document.getElementById('uploadedFileCount').textContent = '1';
    }
}

/**
 * 根据文件名获取图标
 */
function getFileIconFromName(filename) {
    const name = filename.toLowerCase();
    if (name.includes('syslog') || name.includes('process')) return '⚙️';
    if (name.includes('file') || name.includes('audit')) return '📄';
    if (name.includes('netflow') || name.includes('network')) return '🌐';
    if (name.endsWith('.json')) return '📋';
    return '📁';
}

/**
 * 检测日志类型
 */
function detectLogType(filename) {
    const name = filename.toLowerCase();
    if (name.includes('syslog') || name.includes('process')) return '进程日志';
    if (name.includes('file') || name.includes('audit')) return '文件日志';
    if (name.includes('netflow') || name.includes('network')) return '网络日志';
    if (name.endsWith('.json')) return 'JSON格式';
    return '未知类型';
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
window.removeFile = removeFile;
window.uploadFiles = uploadFiles;
window.showModeSelector = showModeSelector;
window.selectUploadMode = selectUploadMode;
window.startDemoMode = startDemoMode;
window.showProcessSection = showProcessSection;
window.hideProcessSection = hideProcessSection;
window.updateProgress = updateProgress;

// 覆盖main.js中的占位函数
window.TraceEye = window.TraceEye || {};
window.TraceEye.loadUploadData = loadUploadData;
