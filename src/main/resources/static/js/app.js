// State management
let state = {
    accessToken: localStorage.getItem('catalog_access_token') || null,
    refreshToken: localStorage.getItem('catalog_refresh_token') || null,
    user: null,
    expiresAt: null,
    timerInterval: null
};
let lastStaleRefreshToken = null;

// DOM ready
document.addEventListener('DOMContentLoaded', () => {
    initApp();
});

function initApp() {
    setupEventListeners();
    if (state.accessToken) {
        verifySession();
    } else {
        updateAuthUI(false);
    }
    loadProducts();
}

function setupEventListeners() {
    // Login form submit
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    // Product form submit
    const productForm = document.getElementById('productForm');
    if (productForm) {
        productForm.addEventListener('submit', handleSaveProduct);
    }

    // Change password form submit
    const passwordForm = document.getElementById('passwordForm');
    if (passwordForm) {
        passwordForm.addEventListener('submit', handleChangePassword);
    }
}

// ==========================================
// Authentication & Session
// ==========================================

async function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;

    try {
        const res = await fetch('/api/auth/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (res.status === 429) {
            const retryAfter = res.headers.get('Retry-After') || '60';
            showToast(`Quá giới hạn tần suất! Vui lòng thử lại sau ${retryAfter} giây.`, 'warn');
            return;
        }

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            showToast(err.detail || 'Sai thông tin đăng nhập', 'error');
            return;
        }

        const data = await res.json();
        saveTokens(data.accessToken, data.refreshToken);
        showToast('Đăng nhập thành công!', 'success');
        await verifySession();
        loadProducts();
    } catch (err) {
        showToast('Lỗi kết nối máy chủ: ' + err.message, 'error');
    }
}

async function verifySession() {
    if (!state.accessToken) {
        updateAuthUI(false);
        return;
    }

    try {
        const res = await fetch('/api/auth/me', {
            headers: { 'Authorization': `Bearer ${state.accessToken}` }
        });

        if (res.ok) {
            const data = await res.json();
            state.user = data;
            state.expiresAt = new Date(data.expiresAt);
            updateAuthUI(true);
            startTokenCountdown();
            inspectCurrentToken();
        } else {
            // Token may be expired, attempt auto-refresh
            if (state.refreshToken) {
                await rotateToken(true);
            } else {
                logoutClientState();
            }
        }
    } catch (err) {
        console.error('Session verify failed', err);
    }
}

async function rotateToken(silent = false) {
    if (!state.refreshToken) {
        showToast('Không tìm thấy refresh token để làm mới!', 'warn');
        return;
    }

    try {
        const res = await fetch('/api/auth/refresh', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refreshToken: state.refreshToken })
        });

        if (res.status === 401) {
            const err = await res.json().catch(() => ({}));
            if (err.code === 'REFRESH_TOKEN_REUSED') {
                showToast('CẢNH BÁO: Phát hiện refresh token bị dùng lại! Chuỗi token đã bị thu hồi.', 'error');
            } else {
                showToast('Refresh token đã hết hạn hoặc không hợp lệ. Vui lòng đăng nhập lại.', 'warn');
            }
            logoutClientState();
            return;
        }

        if (res.status === 429) {
            const retryAfter = res.headers.get('Retry-After') || '60';
            showToast(`Quá giới hạn request! Thử lại sau ${retryAfter} giây.`, 'warn');
            return;
        }

        if (!res.ok) {
            showToast('Làm mới token thất bại', 'error');
            logoutClientState();
            return;
        }

        const oldToken = state.refreshToken;
        const data = await res.json();
        lastStaleRefreshToken = oldToken;
        saveTokens(data.accessToken, data.refreshToken);
        if (!silent) showToast('Xoay vòng Refresh Token thành công!', 'success');
        await verifySession();
    } catch (err) {
        showToast('Lỗi khi làm mới token: ' + err.message, 'error');
    }
}

async function handleLogout() {
    if (!confirm('Bạn có chắc muốn đăng xuất khỏi thiết bị này?')) return;

    try {
        await fetch('/api/auth/logout', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${state.accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ refreshToken: state.refreshToken })
        });
    } catch (e) {
        console.warn('Logout API call failed', e);
    }

    logoutClientState();
    showToast('Đã đăng xuất thiết bị hiện tại', 'success');
    loadProducts();
}

async function handleLogoutAll() {
    if (!confirm('CẢNH BÁO: Thao tác này sẽ vô hiệu hóa TẤT CẢ access token và refresh token trên mọi thiết bị. Tiếp tục?')) return;

    try {
        const res = await fetch('/api/auth/logout-all', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${state.accessToken}` }
        });

        if (res.ok) {
            showToast('Đã đăng xuất khỏi TẤT CẢ thiết bị!', 'warn');
            logoutClientState();
            loadProducts();
        } else {
            showToast('Lỗi khi thực hiện đăng xuất mọi thiết bị', 'error');
        }
    } catch (e) {
        showToast('Lỗi kết nối: ' + e.message, 'error');
    }
}

async function handleChangePassword(e) {
    e.preventDefault();
    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;

    try {
        const res = await fetch('/api/auth/change-password', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${state.accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ currentPassword, newPassword })
        });

        if (res.ok) {
            showToast('Đổi mật khẩu thành công! Toàn bộ phiên cũ đã hết hiệu lực, vui lòng đăng nhập lại.', 'success');
            closeModal('passwordModal');
            logoutClientState();
        } else {
            const err = await res.json().catch(() => ({}));
            showToast(err.detail || 'Mật khẩu hiện tại không đúng', 'error');
        }
    } catch (err) {
        showToast('Lỗi: ' + err.message, 'error');
    }
}

function saveTokens(accessToken, refreshToken) {
    state.accessToken = accessToken;
    state.refreshToken = refreshToken;
    localStorage.setItem('catalog_access_token', accessToken);
    if (refreshToken) {
        localStorage.setItem('catalog_refresh_token', refreshToken);
    }
}

function logoutClientState() {
    state.accessToken = null;
    state.refreshToken = null;
    state.user = null;
    state.expiresAt = null;
    if (state.timerInterval) clearInterval(state.timerInterval);
    localStorage.removeItem('catalog_access_token');
    localStorage.removeItem('catalog_refresh_token');
    updateAuthUI(false);
    document.getElementById('tokenInspector').textContent = '// Chưa có token đang hoạt động';
}

function updateAuthUI(isLoggedIn) {
    const guestPanel = document.getElementById('guestPanel');
    const userPanel = document.getElementById('userPanel');
    const btnAddProduct = document.getElementById('btnAddProduct');

    if (isLoggedIn && state.user) {
        guestPanel.style.display = 'none';
        userPanel.style.display = 'block';

        document.getElementById('userNameDisplay').textContent = state.user.username;
        document.getElementById('userAvatarDisplay').textContent = state.user.username.charAt(0).toUpperCase();

        // Render roles
        const rolesContainer = document.getElementById('userRolesDisplay');
        rolesContainer.innerHTML = '';
        (state.user.roles || []).forEach(r => {
            const span = document.createElement('span');
            span.className = 'role-badge';
            span.textContent = r;
            rolesContainer.appendChild(span);
        });

        // Check if user has SCOPE_product:write or ROLE_ADMIN
        const hasWriteScope = (state.user.roles || []).includes('ROLE_ADMIN');
        if (btnAddProduct) {
            btnAddProduct.style.display = 'inline-flex';
            btnAddProduct.disabled = !hasWriteScope;
            if (!hasWriteScope) {
                btnAddProduct.title = 'Yêu cầu quyền ROLE_ADMIN để tạo sản phẩm';
                btnAddProduct.style.opacity = '0.5';
            } else {
                btnAddProduct.title = 'Tạo sản phẩm mới';
                btnAddProduct.style.opacity = '1';
            }
        }

        const btnLock = document.getElementById('btnLockUserDemo');
        if (btnLock) {
            btnLock.style.display = hasWriteScope ? 'block' : 'none';
        }
    } else {
        guestPanel.style.display = 'block';
        userPanel.style.display = 'none';
        if (btnAddProduct) {
            btnAddProduct.style.display = 'inline-flex';
            btnAddProduct.disabled = true;
            btnAddProduct.style.opacity = '0.4';
            btnAddProduct.title = 'Cần đăng nhập quyền ADMIN để thêm sản phẩm';
        }
        const btnLock = document.getElementById('btnLockUserDemo');
        if (btnLock) {
            btnLock.style.display = 'none';
        }
    }
}

function startTokenCountdown() {
    if (state.timerInterval) clearInterval(state.timerInterval);

    const updateTimer = () => {
        if (!state.expiresAt) return;
        const now = new Date();
        const diffMs = state.expiresAt.getTime() - now.getTime();

        if (diffMs <= 0) {
            document.getElementById('tokenTimerText').textContent = 'Đã hết hạn!';
            document.getElementById('tokenProgressBar').style.width = '0%';
            rotateToken(true);
            return;
        }

        const totalSec = Math.floor(diffMs / 1000);
        const min = Math.floor(totalSec / 60);
        const sec = totalSec % 60;
        document.getElementById('tokenTimerText').textContent = 
            `${min.toString().padStart(2, '0')}:${sec.toString().padStart(2, '0')}`;

        // 15 min TTL = 900 seconds
        const pct = Math.max(0, Math.min(100, (totalSec / 900) * 100));
        document.getElementById('tokenProgressBar').style.width = `${pct}%`;
    };

    updateTimer();
    state.timerInterval = setInterval(updateTimer, 1000);
}

function inspectCurrentToken() {
    if (!state.accessToken) return;
    try {
        const parts = state.accessToken.split('.');
        if (parts.length === 3) {
            const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
            const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
            const displayObj = {
                header: header,
                payload: payload,
                rawLength: state.accessToken.length
            };
            document.getElementById('tokenInspector').textContent = JSON.stringify(displayObj, null, 2);
        }
    } catch (e) {
        document.getElementById('tokenInspector').textContent = state.accessToken;
    }
}

// ==========================================
// Catalog / Products Management
// ==========================================

async function loadProducts() {
    const tbody = document.getElementById('productTableBody');
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted);">Đang tải danh mục sản phẩm...</td></tr>';

    try {
        const res = await fetch('/api/v1/products');
        if (!res.ok) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--accent-rose);">Không thể tải danh sách sản phẩm</td></tr>';
            return;
        }

        const products = await res.json();
        if (products.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted);">Chưa có sản phẩm nào trong hệ thống.</td></tr>';
            return;
        }

        const isAdmin = state.user && (state.user.roles || []).includes('ROLE_ADMIN');

        tbody.innerHTML = products.map(p => `
            <tr>
                <td style="font-weight: 700; color: var(--text-muted);">#${p.id}</td>
                <td>
                    <div style="font-weight: 600; color: #fff;">${escapeHtml(p.name)}</div>
                    <div style="font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(p.description || 'Không có mô tả')}</div>
                </td>
                <td>
                    <span class="price-tag">${formatCurrency(p.price)}</span>
                </td>
                <td style="font-size: 0.8rem; color: var(--text-muted);">
                    ${p.createdAt ? new Date(p.createdAt).toLocaleDateString('vi-VN') : 'N/A'}
                </td>
                <td style="text-align: right;">
                    <button class="btn btn-secondary btn-sm" onclick="openEditProduct(${p.id}, '${escapeQuote(p.name)}', '${escapeQuote(p.description || '')}', ${p.price})" ${!isAdmin ? 'disabled style="opacity: 0.4;"' : ''}>Sửa</button>
                    <button class="btn btn-danger btn-sm" onclick="handleDeleteProduct(${p.id})" ${!isAdmin ? 'disabled style="opacity: 0.4;"' : ''}>Xóa</button>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--accent-rose);">Lỗi: ${err.message}</td></tr>`;
    }
}

function openAddProduct() {
    if (!state.accessToken) {
        showToast('Vui lòng đăng nhập bằng tài khoản ADMIN để thêm sản phẩm', 'warn');
        return;
    }
    document.getElementById('modalProductTitle').textContent = 'Thêm sản phẩm mới';
    document.getElementById('productId').value = '';
    document.getElementById('productName').value = '';
    document.getElementById('productDescription').value = '';
    document.getElementById('productPrice').value = '';
    openModal('productModal');
}

function openEditProduct(id, name, description, price) {
    if (!state.accessToken) {
        showToast('Vui lòng đăng nhập để thực hiện thao tác', 'warn');
        return;
    }
    document.getElementById('modalProductTitle').textContent = 'Chỉnh sửa sản phẩm';
    document.getElementById('productId').value = id;
    document.getElementById('productName').value = name;
    document.getElementById('productDescription').value = description;
    document.getElementById('productPrice').value = price;
    openModal('productModal');
}

async function handleSaveProduct(e) {
    e.preventDefault();
    const id = document.getElementById('productId').value;
    const name = document.getElementById('productName').value.trim();
    const description = document.getElementById('productDescription').value.trim();
    const price = parseFloat(document.getElementById('productPrice').value);

    const isEdit = !!id;
    const url = isEdit ? `/api/v1/products/${id}` : '/api/v1/products';
    const method = isEdit ? 'PUT' : 'POST';

    try {
        const res = await fetch(url, {
            method: method,
            headers: {
                'Authorization': `Bearer ${state.accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ name, description, price })
        });

        if (res.status === 401) {
            showToast('Phiên làm việc hết hạn hoặc không có token', 'error');
            return;
        }

        if (res.status === 403) {
            showToast('Từ chối truy cập! Thao tác này yêu cầu quyền SCOPE_product:write (ROLE_ADMIN)', 'error');
            return;
        }

        if (res.ok) {
            showToast(isEdit ? 'Cập nhật sản phẩm thành công!' : 'Tạo sản phẩm thành công!', 'success');
            closeModal('productModal');
            loadProducts();
        } else {
            const err = await res.json().catch(() => ({}));
            showToast(err.detail || 'Lỗi khi lưu sản phẩm', 'error');
        }
    } catch (err) {
        showToast('Lỗi: ' + err.message, 'error');
    }
}

async function handleDeleteProduct(id) {
    if (!confirm(`Bạn có chắc chắn muốn xóa sản phẩm #${id}?`)) return;

    try {
        const res = await fetch(`/api/v1/products/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${state.accessToken}` }
        });

        if (res.status === 403) {
            showToast('Không có quyền xóa sản phẩm! Yêu cầu quyền SCOPE_product:write', 'error');
            return;
        }

        if (res.ok || res.status === 204) {
            showToast(`Đã xóa sản phẩm #${id}`, 'success');
            loadProducts();
        } else {
            showToast('Xóa sản phẩm thất bại', 'error');
        }
    } catch (err) {
        showToast('Lỗi: ' + err.message, 'error');
    }
}

// ==========================================
// Modal & Utility
// ==========================================

function openModal(id) {
    const modal = document.getElementById(id);
    if (modal) modal.classList.add('active');
}

function closeModal(id) {
    const modal = document.getElementById(id);
    if (modal) modal.classList.remove('active');
}

function openChangePasswordModal() {
    document.getElementById('currentPassword').value = '';
    document.getElementById('newPassword').value = '';
    openModal('passwordModal');
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;

    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

function formatCurrency(amount) {
    return new Intl.NumberFormat('vi-VN', { style: 'currency', currency: 'VND' }).format(amount);
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;")
              .replace(/</g, "&lt;")
              .replace(/>/g, "&gt;")
              .replace(/"/g, "&quot;")
              .replace(/'/g, "&#039;");
}

function escapeQuote(str) {
    if (!str) return '';
    return str.replace(/'/g, "\\'");
}

function fillLogin(u, p) {
    document.getElementById('loginUsername').value = u;
    document.getElementById('loginPassword').value = p;
}

async function simulateTokenReuseAttack() {
    if (!state.refreshToken) {
        showToast('Vui lòng đăng nhập trước khi chạy test mô phỏng', 'warn');
        return;
    }

    // Bước 1: Nếu chưa có stale token, thực hiện 1 lần rotation hợp lệ
    let staleToUse = lastStaleRefreshToken;
    if (!staleToUse) {
        showToast('Đang thực hiện 1 lần rotation để tạo token cũ đã thu hồi...', 'info');
        const oldToken = state.refreshToken;
        try {
            const res = await fetch('/api/auth/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refreshToken: oldToken })
            });
            if (!res.ok) {
                showToast('Không thể chuẩn bị token cho test', 'error');
                return;
            }
            const data = await res.json();
            staleToUse = oldToken;
            lastStaleRefreshToken = oldToken;
            saveTokens(data.accessToken, data.refreshToken);
            await verifySession();
        } catch (e) {
            showToast('Lỗi: ' + e.message, 'error');
            return;
        }
    }

    // Bước 2: Hacker cố tình dùng lại staleToUse để gửi yêu cầu refresh
    showToast('Mô phỏng Hacker: Đang gửi lại Refresh Token cũ đã bị thu hồi...', 'warn');
    try {
        const res = await fetch('/api/auth/refresh', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refreshToken: staleToUse })
        });

        if (res.status === 401) {
            const err = await res.json().catch(() => ({}));
            if (err.code === 'REFRESH_TOKEN_REUSED') {
                showToast('🚨 [R3 BẢO MẬT KÍCH HOẠT]: Phát hiện Refresh Token bị dùng lại! Toàn bộ họ token đã bị server thu hồi ngay lập tức.', 'error');
                lastStaleRefreshToken = null;
                logoutClientState();
                return;
            }
        }
        showToast('Kết quả: Server trả về HTTP ' + res.status, 'warn');
    } catch (e) {
        showToast('Lỗi mạng: ' + e.message, 'error');
    }
}

async function handleLockDemoUser() {
    if (!confirm('Bạn có chắc muốn KHÓA tài khoản demo "user"?\nToàn bộ token của user này sẽ bị vô hiệu hóa ngay lập tức theo R6.')) return;

    try {
        const res = await fetch('/api/admin/users/user/lock', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${state.accessToken}` }
        });

        if (res.ok || res.status === 204) {
            showToast('🔒 [R6 THÀNH CÔNG]: Đã khóa tài khoản "user"! Mọi access token và refresh token của user này đã bị vô hiệu hóa tức thì.', 'success');
        } else {
            const err = await res.json().catch(() => ({}));
            showToast(err.detail || 'Lỗi khi khóa tài khoản: HTTP ' + res.status, 'error');
        }
    } catch (e) {
        showToast('Lỗi kết nối: ' + e.message, 'error');
    }
}


