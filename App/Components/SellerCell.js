import React, { Component } from 'react'
// import PropTypes from 'prop-types';
import { View, Text, Image, FlatList, TouchableOpacity, TouchableHighlight } from 'react-native'
import {
  Button,
  Card,
  CardItem,
  Left,
  Right,
  Body,
  Thumbnail,
  Icon
} from 'native-base'
import styles from './Styles/SellerCellStyle'
import colors from '../Themes/Colors'

export default class SellerCell extends Component {
  constructor (props) {
    super(props)
    this.state = {
      isShowMore: false
    }
  }

  renderItem (item) {
    return (
      <Image
        style={{
          height: 150,
          width: 100,
          margin: 4
        }}
        source={require('../Images/cogai.png')} />
    )
  }

  handleShowMore = () => {
    this.setState({isShowMore: !this.state.isShowMore})
  }

  render () {
    const featureImageData = [
      {key: 'a'}, {key: 'b'}, {key: 'c'}, {key: 'd'}, {key: 'e'}
    ]

    return (
      <View style={styles.card}>
        <Card>
          <CardItem>
            <TouchableHighlight
              activeOpacity={1}
              underlayColor='#fff'
              style={{flexGrow: 2}}
              onPress={this.props.onPress}>
              <Left>
                <Thumbnail source={require('../Images/LoginBg.png')} />
                <Body>
                  <Text style={styles.title}>Huy Trần</Text>
                  <Text style={styles.price}>Giá bán: 100k</Text>
                  <Text style={styles.address}>FPT University - 1km</Text>
                </Body>
              </Left>
            </TouchableHighlight>
            <Right>
              <TouchableOpacity onPress={this.handleShowMore}>
                <Icon
                  name='ios-chatboxes'
                  style={{color: colors.mainColor, fontSize: 30}} />
              </TouchableOpacity>
            </Right>
          </CardItem>
          <CardItem style={{flexDirection: 'column'}} cardBody>
            <View style={{marginBottom: 8}}>
              <Text>
                Lorem ipsum dolor sit amet, consectetur adipiscing elit.
              </Text>
            </View>
            <FlatList horizontal
              showsHorizontalScrollIndicator={false}
              data={featureImageData}
              renderItem={({item}) => this.renderItem(item)}
            />
          </CardItem>
        </Card>
      </View>
    )
  }
}
