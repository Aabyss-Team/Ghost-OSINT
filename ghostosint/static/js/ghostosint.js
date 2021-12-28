//-------------------------------------------------------------------------------
// Name:         ghostosint.js
// Purpose:      All the javascript code for the ghostosint aspects of the UI.
//
// Author:      Snow Wolf
//
// Created:     2021/12.25
// Copyright:   (c) Snow Wolf (2021)
// Licence:     GPL
//-------------------------------------------------------------------------------

// Toggler for theme
document.addEventListener("DOMContentLoaded", () => {
  const themeToggler = document.getElementById("theme-toggler");
  const head = document.getElementsByTagName("HEAD")[0];
  const togglerText = document.getElementById("toggler-text");
  let link = document.createElement("link");

  if (localStorage.getItem("mode") === "白色秘境") {
    togglerText.innerText = "黑色炫酷";
    document.getElementById("theme-toggler").checked = true; // ensure theme toggle is set to dark
  } else { // initial mode ist null
    togglerText.innerText = "白色秘境";
    document.getElementById("theme-toggler").checked = false; // ensure theme toggle is set to light
  }


  themeToggler.addEventListener("click", () => {
    togglerText.innerText = "白色秘境";

    if (localStorage.getItem("theme") === "dark-theme") {
      localStorage.removeItem("theme");
      localStorage.setItem("mode", "黑色炫酷");
      //localStorage.setItem("mode", "Dark Mode");
      link.rel = "stylesheet";
      link.type = "text/css";
      link.href = "${docroot}/static/css/ghostosint.css";

      head.appendChild(link);
      location.reload();
    } else {
      localStorage.setItem("theme", "dark-theme");
      localStorage.setItem("mode", "白色秘境");
      link.rel = "stylesheet";
      link.type = "text/css";
      link.href = "${docroot}/static/css/dark.css";

      head.appendChild(link);
      location.reload();
    }
  });
});

var GhostOsint = {};

GhostOsint.replace_sfurltag = function (data) {
  if (data.toLowerCase().indexOf("&lt;sfurl&gt;") >= 0) {
    data = data.replace(
      RegExp("&lt;sfurl&gt;(.*)&lt;/sfurl&gt;", "img"),
      "<a target=_new href='$1'>$1</a>"
    );
  }
  if (data.toLowerCase().indexOf("<sfurl>") >= 0) {
    data = data.replace(
      RegExp("<sfurl>(.*)</sfurl>", "img"),
      "<a target=_new href='$1'>$1</a>"
    );
  }
  return data;
};

GhostOsint.remove_sfurltag = function (data) {
  if (data.toLowerCase().indexOf("&lt;sfurl&gt;") >= 0) {
    data = data
      .toLowerCase()
      .replace("&lt;sfurl&gt;", "")
      .replace("&lt;/sfurl&gt;", "");
  }
  if (data.toLowerCase().indexOf("<sfurl>") >= 0) {
    data = data.toLowerCase().replace("<sfurl>", "").replace("</sfurl>", "");
  }
  return data;
};

GhostOsint.search = function (scan_id, value, type, postFunc) {
  GhostOsint.fetchData(
    "/search",
    { id: scan_id, eventType: type, value: value },
    postFunc
  );
};

GhostOsint.deleteScan = function(scan_id, callback) {
    var req = $.ajax({
      type: "GET",
      url: "/scandelete?id=" + scan_id
    });
    req.done(function() {
        alertify.success('<i class="glyphicon glyphicon-ok-circle"></i> <b>扫描已删除</b><br/><br/>' + scan_id.replace(/,/g, "<br/>"));
        GhostOsint.log("已删除的扫描: " + scan_id);
        callback();
    });
    req.fail(function (hr, textStatus, errorThrown) {
        alertify.error('<i class="glyphicon glyphicon-minus-sign"></i> <b>错误了呢~</b><br/></br>' + hr.responseText);
        GhostOsint.log("删除时出现错误的扫描: " + scan_id + ": " + hr.responseText);
    });
};

GhostOsint.stopScan = function(scan_id, callback) {
    var req = $.ajax({
      type: "GET",
      url: "/stopscan?id=" + scan_id
    });
    req.done(function() {
        alertify.success('<i class="glyphicon glyphicon-ok-circle"></i> <b>扫描已中止</b><br/><br/>' + scan_id.replace(/,/g, "<br/>"));
        GhostOsint.log("已中止的扫描: " + scan_id);
        callback();
    });
    req.fail(function (hr, textStatus, errorThrown) {
        alertify.error('<i class="glyphicon glyphicon-minus-sign"></i> <b>错误</b><br/><br/>' + hr.responseText);
        GhostOsint.log("停止扫描时出错的扫描: " + scan_id + ": " + hr.responseText);
    });
};

GhostOsint.fetchData = function (url, postData, postFunc) {
  var req = $.ajax({
    type: "POST",
    url: url,
    data: postData,
    cache: false,
    dataType: "json",
  });

  req.done(postFunc);
  req.fail(function (hr, status) {
      alertify.error('<i class="glyphicon glyphicon-minus-sign"></i> <b>错误</b><br/>' + status);
  });
};

/*
GhostOsint.simpleTable = function(id, data, cols, linkcol=null, linkstring=null, sortable=true, rowfunc=null) {
	var table = "<table id='" + id + "' ";
	table += "class='table table-bordered table-striped tablesorter'>";
	table += "<thead><tr>";
	for (var i = 0; i < cols.length; i++) {
		table += "<th>" + cols[i] + "</th>";
	}
	table += "</tr></thead><tbody>";

	for (var i = 1; i < data.length; i++) {
		table += "<tr>";
		for (var c = 0; c < data[i].length; c++) {
			if (c == linkcol) {
				if (linkstring.indexOf("%%col") > 0) {
				}
				table += "<td>" + <a class='link' onClick='" + linkstring + "'>";
				table += data[i][c] + "</a></td>"
			} else {
				table += "<td>" + data[i][c] + "</td>";
			}
		}
		table += "</tr>";
	}
	table += "</tbody></table>";

	return table;
}

*/

GhostOsint.updateTooltips = function () {
  $(document).ready(function () {
    if ($("[rel=tooltip]").length) {
      $("[rel=tooltip]").tooltip({ container: "body" });
    }
  });
};

GhostOsint.log = function (message) {
  if (typeof console == "object" && typeof console.log == "function") {
    var currentdate = new Date();
    var pad = function (n) {
      return ("0" + n).slice(-2);
    };
    var datetime =
      currentdate.getFullYear() +
      "-" +
      pad(currentdate.getMonth() + 1) +
      "-" +
      pad(currentdate.getDate()) +
      " " +
      pad(currentdate.getHours()) +
      ":" +
      pad(currentdate.getMinutes()) +
      ":" +
      pad(currentdate.getSeconds());
    console.log("[" + datetime + "] " + message);
  }
};
