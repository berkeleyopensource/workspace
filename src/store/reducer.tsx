
var initState = {
  authState: false,
  user: {}
}

var reducer = (state = initState, action) => {
  switch(action.type) {
    case "setState":
      return {...state, action.key: action.value}
  }
}

export default reducer;