#!/usr/bin/python
# Copyright (c) 2018 SwiftStack
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: os_credential
short_description: Manage OpenStack Identity Credentials
extends_documentation_fragment: openstack
author: Tim Burke
version_added: "2.8"
description:
    - Manage OpenStack Identity credentials. Credentials can be created,
      updated or deleted using this module. A credential will be updated
      if I(user), I(project), and I(type) all match an existing
      credential and I(state) is present. The values for I(user), I(project),
      and I(type) cannot be updated without deleting and
      re-creating the credential.
options:
   user:
     required: true
     description:
        - User who will own the credential.
   project:
     required: true
     description:
        - Project for which the credential will apply.
   domain:
     description:
        - Domain to use when looking up I(user) and/or I(project)
          (if the cloud supports domains)
   type:
     required: true
     description:
        - The credential type, such as ec2 or cert. The implementation
          determines the list of supported types.
   blob:
     description:
        - The credential itself, either as a serialized blob or as a dict
          that will be JSON-serialized. Required if state is present.
   state:
     description:
       - Should the resource be present or absent.
     choices: [present, absent]
     default: present
requirements:
    - "python >= 2.7"
    - "openstacksdk"
'''

EXAMPLES = '''
# Create a credential using a string
- os_credential:
    cloud: mycloud
    state: present
    user: demouser
    project: demo
    type: ec2
    blob: '{"access":"181920","secret":"secretKey"}'

# Create a credential using a dict
- os_credential:
    cloud: mycloud
    state: present
    domain: default
    user: demouser
    project: demo
    type: ec2
    blob:
        access: "181920"
        secret: secretKey

# Delete a credential
- os_credential:
    cloud: mycloud
    state: absent
    user: demouser
    project: demo
    type: ec2
'''


RETURN = '''
credential:
    description: Dictionary describing the credential.
    returned: On success when I(state) is 'present'
    type: complex
    contains:
        id:
            description: Credential ID.
            type: str
            sample: "207e9b76935efc03804d3dd6ab52d22e9b22a0711e4ada4ff8b76165a07311d7"
        user_id:
            description: Credential user ID.
            type: str
            sample: "bb5476fd12884539b41d5a88f838d773"
        project_id:
            description: Credential project ID.
            type: str
            sample: "6e01855f345f4c59812999b5e459137d"
        type:
            description: Credential type.
            type: str
            sample: "ec2"
        blob:
            description: Credential data.
            type: str
            sample: "{\"access\": \"a42a27755ce6442596b049bd7dd8a563\", \"secret\": \"71faf1d40bb24c82b479b1c6fbbd9f0c\", \"trust_id\": null}"
'''

import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.openstack import (
    openstack_full_argument_spec, openstack_module_kwargs, openstack_cloud_from_module,
    openstack_get_domain_id
)


def main():
    argument_spec = openstack_full_argument_spec(
        type=dict(required=True, type='str'),
        user=dict(required=True),
        project=dict(required=True),
        blob=dict(required=False, default=None, type='raw'),
        domain=dict(required=False, default=None),
        state=dict(default='present', choices=['absent', 'present']),
    )

    module_kwargs = openstack_module_kwargs()
    module = AnsibleModule(
        argument_spec,
        **module_kwargs)

    cred_type = module.params['type']
    cred_data = module.params['blob']
    user = module.params['user']
    project = module.params['project']
    domain = module.params['domain']
    state = module.params['state']

    if state == 'present' and not cred_data:
        module.fail_json(msg='Credential blob is required if state is present')

    sdk, cloud = openstack_cloud_from_module(module)
    try:
        domain_id = None
        if domain:
            domain_id = openstack_get_domain_id(cloud, domain)

        if domain_id:
            user_obj = cloud.get_user(user, domain_id=domain_id)
        else:
            user_obj = cloud.get_user(user)
        if not user:
            module.fail_json(msg='User %s is not valid' % user)

        if domain_id:
            project_obj = cloud.get_project(project, domain_id=domain_id)
        else:
            project_obj = cloud.get_project(project)
        if not project:
            module.fail_json(msg='Project %s is not valid' % project)

        credentials = [
            c for c in cloud.identity.credentials(
                type=cred_type, user_id=user_obj['id'])
            if c.project_id == project_obj['id']
        ]

        if not credentials:
            cred = None
        elif len(credentials) > 1:
            module.fail_json(msg='Multiple %s credentials found for user %s and project %s' % (
                cred_type, user, project))
        else:
            cred = credentials[0]

        if state == 'present':
            if not isinstance(cred_data, str):
                cred_data = json.dumps(cred_data)

            if cred is None:
                cred = cloud.identity.create_credential(
                    type=cred_type, user_id=user_obj['id'],
                    project_id=project_obj['id'], blob=cred_data)
                changed = True
            elif cred.blob != cred_data:
                cred = cloud.identity.update_credential(
                    cred['id'], blob=cred_data)
                changed = True
            else:
                changed = False
            module.exit_json(changed=changed, credential=cred)

        elif state == 'absent':
            if cred is None:
                changed = False
            else:
                cloud.identity.delete_credential(cred['id'])
                changed = True
            module.exit_json(changed=changed)

    except sdk.exceptions.OpenStackCloudException as e:
        module.fail_json(msg=str(e), extra_data=e.extra_data)


if __name__ == '__main__':
    main()
