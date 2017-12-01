import React, { Component } from 'react'
import { ScrollView, Text, KeyboardAvoidingView, FlatList } from 'react-native'
import { connect } from 'react-redux'
// Add Actions - replace 'Your' with whatever your reducer is called :)
// import YourActions from '../Redux/YourRedux'
import ListBookActions from '../Redux/ListBookRedux'

// Styles
import {
  Container,
  Content,
  Header,
  Item,
  Button,
  Icon,
  Input
} from 'native-base'
import Navigation from '../Components/Navigation'
import styles from './Styles/FullBookScreenStyle'
import FullBookCell from '../Components/FullBookCell'
class FullBookScreen extends Component {
  constructor (props) {
    super(props)
    this.state = {
      inputValue: ''
    }
  }

  componentWillMount () {
    this.props.fetchBookList()
  }

  renderItem (item) {
    return <FullBookCell item={item} onPressItemSearch={this.props.navigation.state.params.onPressItemSearch} />
  }

  render () {
    return (
      <Container>
        <Navigation onPressBack={() => this.props.navigation.goBack()}
          title={this.props.navigation.state.params.book.section} />
        <Content>
          <Header searchBar rounded>
            <Item>
              <Icon name='ios-search' />
              <Input placeholder='Search'
                onChangeText={(text) => {
                  this.setState({
                    inputValue: text
                  })
                }} />
              <Icon name='ios-people' />
            </Item>
            <Button transparent>
              <Text>Search</Text>
            </Button>
          </Header>
          {this.props.payload && <FlatList
            data={this.props.payload}
            keyExtractor={(item) => item.id}
            renderItem={({item}) => this.renderItem(item)}
          />}
        </Content>
      </Container>
    )
  }
}

const mapStateToProps = (state) => {
  const { payload } = state.listBook
  return {
    payload
  }
}

const mapDispatchToProps = (dispatch) => {
  return {
    fetchBookList: () => dispatch(ListBookActions.listBookRequest())
  }
}

export default connect(mapStateToProps, mapDispatchToProps)(FullBookScreen)
