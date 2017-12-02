import React, { Component } from 'react'
import {
  AsyncStorage
} from 'react-native'
import { connect } from 'react-redux'
// Add Actions - replace 'Your' with whatever your reducer is called :)
// import YourActions from '../Redux/YourRedux'
import AddFavoriteBookActions from '../Redux/AddFavoriteBookRedux'

// Styles
import {
  Container,
  Content,
  Card,
  ListItem,
  Button,
  CardItem,
  Badge
} from 'native-base'
import styles from './Styles/BookDetailScreenStyle'
import BookContent from '../Components/BookContent'
import BookCommentScreen from './BookCommentScreen'
import Navigation from '../Components/Navigation'
import ContentBook from '../Components/ContentBook'
import CommentDetail from '../Components/CommentDetail'
import ListMain from '../Components/ListMain'
class BookDetailScreen extends Component {
  constructor (props) {
    super(props)
    this.onAddBookPress = this.onAddBookPress.bind(this)
  }

  componentWillMount () {
  }
  componentDidMount () {
    // this.props.fetchBook(this.props.navigation.state.params.bookId)
  }

  onAddBookPress (item) {
    console.log('Add Book Press')
    this.props.navigation.navigate('AddBookScreen', {item: item})
  }

  onSendPress (value) {
    console.log('Value:  ', value)
  }
  onSendComment (comment) {
    console.log('Comment:  ', comment)
    // let data = this.state.dataComment
    // data.shift()
    // this.setState({
    //   dataComment: data.concat([{key: 'a'}])
    // })
  }

  onPressFavorite = (bookId) => {
    AsyncStorage.getItem('@BookSharing:token')
    .then((res) => {
      this.props.addFavoriteBook({token: res, bookId})
    })
    .catch((error) => console.log(error))
  }

  render () {
    const { navigation } = this.props
    const item = navigation.state.params.book
    return (
      item && <Container>
        <Navigation onPressBack={() => navigation.goBack()}
          title={item.name} />
        <Content>
          <BookContent
            onPressFavorite={() => this.onPressFavorite(item.id)}
            navigation={navigation}
            item={item}
            onAddBookPress={this.onAddBookPress} />
          <ContentBook />
          <CommentDetail onSendComment={this.onSendComment.bind(this)} />
          <BookCommentScreen bookId={item.id} />
          {/* <ListMain items={[]} /> */}
        </Content>
      </Container>
    )
  }
}

const mapStateToProps = (state) => {
  const { payload } = state.addFavoriteBook
  return {
    payload
  }
}

const mapDispatchToProps = (dispatch) => {
  return {
    addFavoriteBook: ({token, bookId}) =>
      dispatch(AddFavoriteBookActions.addFavoriteBookRequest({token, bookId}))
  }
}

export default connect(mapStateToProps, mapDispatchToProps)(BookDetailScreen)
