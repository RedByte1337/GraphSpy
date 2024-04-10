// ========== Access Tokens ==========

function setActiveAccessToken(access_token_id) {
    var active_access_token = access_token_id;
    setCookie("access_token_id", active_access_token);
    let response = $.ajax({
        type: "GET",
        async: false,
        url: "/api/active_access_token/" + active_access_token
    });
    if (document.getElementById("access_token_id")) {
        document.getElementById("access_token_id").value = active_access_token;
    }
    obtainAccessTokenInfo();
    bootstrapToast("Activate Access Token", `[Succes] Activated access token with ID '${active_access_token}'`);
};

function getActiveAccessToken(access_token_field = null) {
    let response = $.ajax({
        type: "GET",
        async: false,
        url: "/api/active_access_token"
    });
    active_access_token = response.responseText
    setCookie("access_token_id", active_access_token);
    if (access_token_field) {
        access_token_field.value = active_access_token;
    }
};

function deleteAccessToken(token_id) {
    let response = $.ajax({
        type: "GET",
        async: false,
        url: "/api/delete_access_token/" + token_id
    });
    bootstrapToast("Delete access token", `[Success] Deleted access token with ID ${token_id}.`);
};

// ========== Refresh Tokens ==========

function setActiveRefreshToken(refresh_token_id) {
    var active_refresh_token = refresh_token_id;
    setCookie("refresh_token_id", active_refresh_token);
    let response = $.ajax({
        type: "GET",
        async: false,
        url: "/api/active_refresh_token/" + active_refresh_token
    });
    if (document.getElementById("refresh_token_id")) {
        document.getElementById("refresh_token_id").value = active_refresh_token;
    }
    obtainRefreshTokenInfo();
    bootstrapToast("Activate Refresh Token", `[Succes] Activated refresh token with ID '${active_refresh_token}'`);
};

function getActiveRefreshToken(refresh_token_field) {
    let response = $.ajax({
        type: "GET",
        async: false,
        url: "/api/active_refresh_token"
    });
    active_refresh_token = response.responseText
    setCookie("refresh_token_id", active_refresh_token);
    if (refresh_token_field) {
        refresh_token_field.value = active_refresh_token
    }
};

function refreshToAccessToken(refresh_token_id, resource, client_id, store_refresh_token = false, activate = false) {
    var post_data = {
        "refresh_token_id": refresh_token_id,
        "resource": resource,
        "client_id": client_id
    };
    if (store_refresh_token) {
        post_data["store_refresh_token"] = 1;
    }
    let response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/refresh_to_access_token",
        data: post_data
    });
    access_token_id = response.responseText;
    if (Number.isInteger(parseInt(access_token_id))) {
        bootstrapToast("Refresh To Access Token", `[Succes] Obtained access token with ID '${access_token_id}'`);
        if (activate) {
            setActiveAccessToken(access_token_id);
        }
    } else {
        bootstrapToast("Refresh To Access Token", '[Error] Failed to obtain an access token.');
    }
};

function deleteRefreshToken(token_id) {
    let response = $.ajax({
        type: "GET",
        async: false,
        url: "/api/delete_refresh_token/" + token_id
    });
    bootstrapToast("Delete refresh token", `[Success] Deleted refresh token with ID ${token_id}.`);
}

// ========== Device Codes ==========

function generateDeviceCode(resource, client_id) {
    let response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/generate_device_code",
        data: { "resource": resource, "client_id": client_id }
    });
    bootstrapToast("Device Code", `[Success] Generated Device Code with User Code '${response.responseText}'.`, "primary");
    reloadTables();
}

function restartDeviceCodePolling() {
    let response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/restart_device_code_polling"
    });
    $('#device_codes').DataTable().ajax.reload(null, false);
    bootstrapToast("Restart polling", response.responseText);
}

// ========== Graph ==========


function graphDownload(drive_id, item_id, access_token_id) {
    let graph_uri = "https://graph.microsoft.com/v1.0/drives/" + drive_id + "/items/" + item_id
    let response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/generic_graph",
        dataSrc: "",
        data: { "graph_uri": graph_uri, "access_token_id": access_token_id },
    });
    let response_json = JSON.parse(response.responseText)
    window.location = response_json["@microsoft.graph.downloadUrl"];
}

// ========== Database ==========

function deleteDatabase(database_name) {
    let response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/delete_database",
        data: { "database": database_name }
    });
    bootstrapToast("Delete database", response.responseText)
}

function activateDatabase(database_name) {
    let response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/activate_database",
        data: { "database": database_name }
    });
    obtainAccessTokenInfo();
    obtainRefreshTokenInfo();
    obtainPersistentSettings();
    bootstrapToast("Acticate database", response.responseText)
}

function createDatabase(database_name) {
    let response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/create_database",
        data: { "database": database_name }
    });
    obtainAccessTokenInfo();
    obtainRefreshTokenInfo();
    obtainPersistentSettings();
    bootstrapToast("Create database", response.responseText)
}

function duplicateDatabase(database_name) {
    let response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/duplicate_database",
        data: { "database": database_name }
    });
    bootstrapToast("Duplicate database", response.responseText)
}

// ========== Settings ==========

function setTableErorMessages(state) {
    let response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/set_table_error_messages",
        data: { "state": state }
    });
    bootstrapToast("DataTable Error Messages", response.responseText)
    $('#dt-error-message-button-disabled').toggleClass("active")
    $('#dt-error-message-button-enabled').toggleClass("active")
}

// ========== User Agent ==========

function getUserAgent() {
    let response = $.ajax({
        type: "GET",
        async: false,
        url: "/api/get_user_agent"
    });
    if (response.status == 200) {
        return response.responseText
    }
    return "Unable to obtain user agent."
}

function setUserAgent(userAgent) {
    let response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/set_user_agent",
        data: { "user_agent": userAgent }
    });
    bootstrapToast("Set User Agent", response.responseText)
}

// ========== Cookies ==========

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
};

function setCookie(name, value) {
    var today = new Date();
    var expiry = new Date(today.getTime() + 30 * 24 * 3600 * 1000);
    document.cookie = name + "=" + escape(value) + "; path=/; expires=" + expiry.toGMTString();
};

// ========== Helpers ==========

function copyToClipboard(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text);
    } else {
        const tmp = document.createElement('TEXTAREA');
        const focus = document.activeElement;

        tmp.value = text;

        document.body.appendChild(tmp);
        tmp.select();
        document.execCommand('copy');
        document.body.removeChild(tmp);
        focus.focus();
    }
    var messageTruncated = ((text.length > 100) ? `${text.substr(0, 100)}...` : text)
    bootstrapToast("Copy to clipboard", `Copied to clipboard: '${messageTruncated}'`);
}

function reloadTables() {
    $('table.dataTable').DataTable().ajax.reload(null, false);
}

function prettifyXml(sourceXml) {
    var xmlDoc = new DOMParser().parseFromString(sourceXml, 'application/xml');
    var xsltDoc = new DOMParser().parseFromString([
        // describes how we want to modify the XML - indent everything
        '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">',
        '  <xsl:strip-space elements="*"/>',
        '  <xsl:template match="para[content-style][not(text())]">', // change to just text() to strip space in text nodes
        '    <xsl:value-of select="normalize-space(.)"/>',
        '  </xsl:template>',
        '  <xsl:template match="node()|@*">',
        '    <xsl:copy><xsl:apply-templates select="node()|@*"/></xsl:copy>',
        '  </xsl:template>',
        '  <xsl:output indent="yes"/>',
        '</xsl:stylesheet>',
    ].join('\n'), 'application/xml');

    var xsltProcessor = new XSLTProcessor();
    xsltProcessor.importStylesheet(xsltDoc);
    var resultDoc = xsltProcessor.transformToDocument(xmlDoc);
    var resultXml = new XMLSerializer().serializeToString(resultDoc);
    if (resultXml.includes("parsererror")) {
        return sourceXml;
    }
    return resultXml;
};

// ========== Messages ==========

function bootstrapAlert(message, type) {
    // Types: primary, secondary, success, danger, warning, info, light, dark
    var type_class = `alert-${type}`;
    var dom = $('<div>');
    dom.addClass("alert alert-dismissible");
    validTypes = ["primary", "secondary", "success", "danger", "warning", "info", "light", "dark"]
    if (type && validTypes.includes(type.toLowerCase())) {
        dom.addClass(`alert-${type.toLowerCase()}`);
    }
    dom.attr("role", "alert");
    dom.text(message);
    dom.append($('<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>'));
    $('#alert_placeholder').append(dom);
}

function bootstrapToast(title, message, type = null, alternative = false) {
    // Types: primary, secondary, success, danger, warning, info, light, dark
    // Wrapper for new Toast Message
    var toast_wrapper = $('<div class="toast" role="alert" aria-live="assertive" aria-atomic="true"></div>');
    validTypes = ["primary", "secondary", "success", "danger", "warning", "info", "light", "dark"]
    if (type && validTypes.includes(type.toLowerCase())) {
        if (alternative) {
            toast_wrapper.addClass(`bg-${type.toLowerCase()}-subtle`).addClass(`text-${type.toLowerCase()}-emphasis`);
        } else {
            toast_wrapper.addClass(`text-bg-${type.toLowerCase()}`);
        }
    }
    // Toast header
    var toast_header = $('<div class="toast-header"><small>Just now</small><button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Close"></button></div>');
    var toast_title = $('<strong class="me-auto"></strong>');
    toast_title.text(title);
    toast_header.prepend(toast_title);
    // Toast body
    var toast_body = $('<div class="toast-body"></div>');
    toast_body.text(message);
    // Append header and body to toast wrapper
    toast_wrapper.append(toast_header);
    toast_wrapper.append(toast_body);
    // Append new Toast Message to the page
    $('#toast_placeholder').append(toast_wrapper);
    // Activate the last Toast Message
    const toastList = [...$(".toast")].map(toastEl => new bootstrap.Toast(toastEl, "show"))
    toastList[toastList.length - 1].show()
}
