document.fonts.ready.then(function () {
	document.getElementsByTagName("main")[0].style.minHeight = "calc(100% - 48px - " + document.getElementsByTagName("header")[0].offsetHeight.toString() + "px)";
}); // Resize height of main to accomodate height of header after fonts are loaded

if (document.getElementsByClassName("listing").length == 0) {
	document.getElementById("noResults").style.display = "block";
}

function search() {
	var input = document.getElementById('searchbar').value.toUpperCase();
	var listings = document.getElementsByClassName("listing");
	var found = false;

	for (i = 0; i < listings.length; i++) {
		var text = listings[i].getElementsByTagName("h3")[0].innerText
		
		if (text.toUpperCase().indexOf(input) > -1) {
			listings[i].style.display = "";
			found = true;
		} else {
			listings[i].style.display = "none";
		}
	}
	
	if (!found) {
		document.getElementById("noResults").style.display = "block";
	} else {
		document.getElementById("noResults").style.display = "none";
	}
}
