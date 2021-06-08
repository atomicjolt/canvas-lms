/*
 * Copyright (C) 2021 - present Instructure, Inc.
 *
 * This file is part of Canvas.
 *
 * Canvas is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, version 3 of the License.
 *
 * Canvas is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 */

import React from 'react'
import OutcomesPopover from './OutcomesPopover'

export default {
  title: 'Examples/Outcomes/OutcomesPopover',
  component: OutcomesPopover,
  args: {
    outcomes: [
      {_id: 1, title: 'Outcome 1'},
      {_id: 2, title: 'Outcome 2 Outcome Outcome Outcome'},
      {
        _id: 3,
        title: 'Outcome 3 Outcome 3 Outcome 3 Outcome 3 Outcome 3 Outcome 3 Outcome 3 Outcome 3'
      }
    ]
  }
}

const Template = args => <OutcomesPopover {...args} />
export const Default = Template.bind({})

export const MoreThan10 = Template.bind({})
MoreThan10.args = {
  outcomes: new Array(20).fill(0).map((_v, i) => ({
    _id: i,
    title: `Outcome ${i + 1}`
  }))
}

export const ReallyLongTitles = Template.bind({})
ReallyLongTitles.args = {
  outcomes: new Array(20).fill(0).map((_v, i) => ({
    _id: i,
    title: `Outcome ${i + 1} `.repeat(10)
  }))
}
