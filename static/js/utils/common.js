/**
 * 通用工具函数
 */

// 转义HTML特殊字符
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// 格式化时间
function formatTime(timestamp) {
    if (!timestamp) return '-';
    const date = new Date(timestamp);
    return date.toLocaleString('zh-CN');
}

// 格式化文件大小
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 显示模态框
function showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'flex';
    }
}

// 隐藏模态框
function hideModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
    }
}

// 显示加载状态
function showLoading(containerId, message = '加载中...') {
    const container = document.getElementById(containerId);
    if (container) {
        container.innerHTML = `
            <div class="loading">
                <div class="loading-spinner"></div>
                <p>${message}</p>
            </div>
        `;
    }
}

// 显示空状态
function showEmptyState(containerId, icon = '📭', title = '暂无数据', description = '') {
    const container = document.getElementById(containerId);
    if (container) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">${icon}</div>
                <div class="empty-state-title">${title}</div>
                ${description ? `<div class="empty-state-desc">${description}</div>` : ''}
            </div>
        `;
    }
}

// 防抖函数
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// 节流函数
function throttle(func, limit) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// 深拷贝
function deepClone(obj) {
    if (obj === null || typeof obj !== 'object') return obj;
    if (obj instanceof Date) return new Date(obj.getTime());
    if (obj instanceof Array) return obj.map(item => deepClone(item));
    const clonedObj = {};
    for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
            clonedObj[key] = deepClone(obj[key]);
        }
    }
    return clonedObj;
}

// 生成唯一ID
function generateId() {
    return 'id_' + Math.random().toString(36).substr(2, 9);
}

// 获取文件图标
function getFileIcon(type) {
    const icons = {
        'process': '⚙️',
        'file': '📄',
        'network': '🌐',
        'json': '📋'
    };
    return icons[type] || '📁';
}

// 获取类型标签
function getTypeLabel(type) {
    const labels = {
        'process': '进程日志',
        'file': '文件日志',
        'network': '网络日志',
        'json': 'JSON日志'
    };
    return labels[type] || '未知类型';
}

// 获取威胁图标
function getThreatIcon(level) {
    const icons = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢'
    };
    return icons[level] || '⚪';
}

// 获取威胁标签
function getThreatLabel(level) {
    const labels = {
        'critical': '严重威胁',
        'high': '高危威胁',
        'medium': '中危威胁',
        'low': '低危威胁'
    };
    return labels[level] || '未知';
}

// 模态框关闭事件绑定
function initModalCloseEvents() {
    // 所有模态框关闭按钮
    document.querySelectorAll('.modal-close').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const modal = e.target.closest('.modal');
            if (modal) modal.style.display = 'none';
        });
    });

    // 点击模态框外部关闭
    window.addEventListener('click', (e) => {
        if (e.target.classList.contains('modal')) {
            e.target.style.display = 'none';
        }
    });
}

// 初始化函数
document.addEventListener('DOMContentLoaded', () => {
    initModalCloseEvents();
});
