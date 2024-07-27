// ========== Access Tokens ==========

function setActiveAccessToken(access_token_id, silent = false) {
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
    if (!silent) {
        bootstrapToast("Activate Access Token", `[Succes] Activated access token with ID '${active_access_token}'`, "info");
    }
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
    bootstrapToast("Activate Refresh Token", `[Succes] Activated refresh token with ID '${active_refresh_token}'`, "info");
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

function refreshToAccessToken(refresh_token_id, client_id, resource = "", scope = "", store_refresh_token = false, activate = false, api_version = 1) {
    var post_data = {
        "refresh_token_id": refresh_token_id,
        "client_id": client_id,
        "resource": resource,
        "scope": scope,
        "api_version": api_version
    };
    if (store_refresh_token) {
        post_data["store_refresh_token"] = 1;
    }
    let response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/refresh_to_access_token",
        data: post_data,
        success: function (response) {
            access_token_id = response;
            if (activate) {
                setActiveAccessToken(access_token_id, true);
                bootstrapToast("Refresh To Access Token", `[Succes] Obtained and activated access token with ID '${access_token_id}'`, "success");
            } else {
                bootstrapToast("Refresh To Access Token", `[Succes] Obtained access token with ID '${access_token_id}'`, "success");
            }
        },
        error: function (xhr, status, error) {
            bootstrapToast("Refresh To Access Token", xhr.responseText, "danger");
        }
    });
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

// ========== MFA ==========

function validateCaptcha(access_token_id, challenge_id, captcha_solution, azure_region, challenge_type) {
    $.ajax({
        type: "POST",
        async: false,
        url: "/api/validate_captcha",
        data: {
            "access_token_id": access_token_id,
            "challenge_id": challenge_id,
            "captcha_solution": captcha_solution,
            "azure_region": azure_region,
            "challenge_type": challenge_type
        },
        success: function (response) {
            bootstrapToast("Validate Captcha", "Captcha solved! Try submitting the previous form again!", "success");
        },
        error: function (xhr, status, error) {
            bootstrapToast("Validate Captcha", xhr.responseText, "danger");
        }
    });
}

function verifySecurityInfo(access_token_id, security_info_type, verification_context, verification_data) {
    $.ajax({
        type: "POST",
        async: false,
        url: "/api/verify_security_info",
        data: {
            "access_token_id": access_token_id,
            "security_info_type": security_info_type,
            "verification_context": verification_context,
            "verification_data": verification_data
        },
        success: function (response) {
            if (response.hasOwnProperty("ErrorCode") && response.ErrorCode) {
                bootstrapToast("Verify Security Info", `An error occurred when trying to validate the provided info. Received Error Code ${response.ErrorCode}`, "danger");
                return;
            }
            bootstrapToast("Verify Security Info", "Info validated. Check if the MFA method was added correctly.", "success");
            $("#add_mfa_form #verification_container").hide();
            $("#add_mfa_form #user_input").val("");
        },
        error: function (xhr, status, error) {
            bootstrapToast("Verify Security Info", xhr.responseText, "danger");
        }
    });
}

function deleteSecurityInfo(access_token_id, security_info_type, data) {
    $.ajax({
        type: "POST",
        async: false,
        url: "/api/delete_security_info", dataType: "json",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify({
            "access_token_id": access_token_id,
            "security_info_type": security_info_type,
            "data": data
        }),
        success: function (response) {
            let successMessage = response.hasOwnProperty("DefaultMethodUpdated") && response.DefaultMethodUpdated ? `MFA Method deleted and default method updated to method type ${response.UpdatedDefaultMethod}` : "MFA Method deleted."
            bootstrapToast("Delete MFA Method", successMessage, "success");
        },
        error: function (xhr, status, error) {
            bootstrapToast("Delete MFA Method", xhr.responseText, "danger");
        }
    });
}

function generateOtpCode(secret_key) {
    response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/generate_otp_code",
        data: {
            "secret_key": secret_key,
        }
    });
    if (response.status != 200) {
        bootstrapToast("Generate OTP Code", response.responseText, "danger");
        return false;
    }
    return response.responseText
}

function deleteGraphspyOtp(otp_code_id) {
    response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/delete_graphspy_otp",
        data: {
            "otp_code_id": otp_code_id,
        },
        success: function (response) {
            bootstrapToast("Delete OTP Code", response, "success");
        },
        error: function (xhr, status, error) {
            bootstrapToast("Delete OTP Code", xhr.responseText, "danger");
        }
    });
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

function graphUpload(drive_id, path, file, access_token_id, callback) {
    base_url = drive_id == "onedrive" ? "https://graph.microsoft.com/v1.0/me/drive" : `https://graph.microsoft.com/v1.0/drives/${drive_id}`;
    let formData = new FormData();
    formData.append("file", file);
    formData.append("upload_uri", `${base_url}/root:/${path}/${file.name}:/content`);
    formData.append("access_token_id", access_token_id);

    $.ajax({
        url: "/api/generic_graph_upload",
        type: "POST",
        data: formData,
        processData: false,
        contentType: false,
        success: function(response) {
            bootstrapToast("Upload File", "File uploaded successfully.", "success");
            if (callback) callback();
        },
        error: function(xhr, status, error) {
            bootstrapToast("Upload File", "Failed to upload file. Status code: " + xhr.status + ", Response: " + xhr.responseText, "danger");
            if (callback) callback();
        }
    });
}
function graphDelete(drive_id, item_id, access_token_id, callback) {
    let graph_uri = `https://graph.microsoft.com/v1.0/drives/${drive_id}/items/${item_id}`
    let response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/custom_api_request",
        dataSrc: "",
        dataType: "json",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify({
            "uri": graph_uri,
            "access_token_id": access_token_id,
            "method": "DELETE"
        }),
        success: function (response) {
            if ([200, 204].includes(response.response_status_code)) {
                bootstrapToast("Delete Item", "Item deleted successfully.", "success");
            } else {
                bootstrapToast("Delete Item", "Failed to delete item. Status code: " + response.response_status_code + ", Response: " + response.response_text, "danger");
            }
            if (callback) callback();
        },
        error: function (xhr, status, error) {
            bootstrapToast("Delete Item", "Failed to delete item. Status code: " + xhr.status + ", Response: " + xhr.responseText, "danger");
            if (callback) callback();
        }
    });
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

// ========== Teams ==========

function getTeamsConversations(access_token_id) {
    let response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/get_teams_conversations",
        data: { "access_token_id": access_token_id }
    });
    if (response.status >= 400) {
        bootstrapToast("Teams Conversations", response.responseText, "danger");
        return;
    }
    return response.responseJSON;
}

function getTeamsConversationMessages(access_token_id, conversation_link) {
    let response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/get_teams_conversation_messages",
        data: { "access_token_id": access_token_id, "conversation_link": conversation_link }
    });
    if (response.status >= 400) {
        bootstrapToast("Teams Conversation Messages", response.responseText, "danger");
        return;
    }
    return response.responseJSON;
}

function sendTeamsConversationMessage(access_token_id, conversation_link, message_content) {
    let response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/send_teams_conversation_message",
        data: {
            "access_token_id": access_token_id,
            "conversation_link": conversation_link,
            "message_content": message_content
        }
    });
    if (response.status >= 400) {
        bootstrapToast("Send Teams Messages", response.responseText, "danger");
        return;
    }
    bootstrapToast("Send Teams Messages", `Teams message with ID ${response.responseText} created.`, "success");
    return response.responseText;
}

function getTeamsConversationMembers(access_token_id, conversation_id) {
    let response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/get_teams_conversation_members",
        data: { "access_token_id": access_token_id, "conversation_id": conversation_id }
    });
    if (response.status >= 400) {
        bootstrapToast("Teams Members", response.responseText, "danger");
        return;
    }
    return response.responseJSON;
}

function getTeamsUserDetails(access_token_id, user_id, external=false) {
    let response = $.ajax({
        type: "GET",
        async: false,
        url: `/api/get_teams_user_details?access_token_id=${access_token_id}&user_id=${user_id}&external=${external.toString()}`
    });
    if (response.status >= 400) {
        bootstrapToast("Get Teams User Details", response.responseText, "danger");
        return;
    }
    return response.responseJSON;
}

function createTeamsConversation(access_token_id, members, type = "group_chat", topic = null, message_content = null) {
    body = {
        "access_token_id": access_token_id,
        "members": members,
        "type": type
    };
    if (topic){
        body["topic"] = topic
    };
    if (message_content){
        body["message_content"] = message_content
    };
    let response = $.ajax({
        type: "POST",
        async: false,
        url: "/api/create_teams_conversation",
        dataType: "json",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify(body)
    });
    if (response.status >= 400) {
        bootstrapToast("Create Teams Conversation", response.responseText, "danger");
        return;
    }
    bootstrapToast("Create Teams Conversation", `Successfully created ${response.responseJSON.length} conversation(s).`, "success");
    return response.responseJSON;
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
